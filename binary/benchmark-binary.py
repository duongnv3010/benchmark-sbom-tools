#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

# ==============================
# Cấu hình cơ bản
# ==============================
DEFAULT_REPO_LIST = "repo-java-binary.txt"
DEFAULT_OUTPUT = "result-java-binary-5.csv"
# mvn/mvnw sẽ được kiểm tra theo từng repo, nên không bắt buộc ở đây
REQUIRED_TOOLS = ["git", "syft", "trivy", "cdxgen", "sbomqs"]

TOOLS = ["syft", "trivy", "cdxgen"]


# ==============================
# Hàm tiện ích
# ==============================
def check_tools():
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        print("[FATAL] Thiếu các tool sau trong PATH:", ", ".join(missing), file=sys.stderr)
        sys.exit(1)


def run_cmd(cmd, cwd=None, env=None):
    start = time.time()
    try:
        p = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
        )
        elapsed = time.time() - start
        return {
            "ok": p.returncode == 0,
            "exit_code": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "elapsed": elapsed,
        }
    except FileNotFoundError as e:
        elapsed = time.time() - start
        return {
            "ok": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"FileNotFoundError: {e}",
            "elapsed": elapsed,
        }


def write_log(log_path: Path, cmd, res):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as f:
        f.write(f"$ {' '.join(cmd)}\n")
        f.write(f"exit_code: {res['exit_code']}\n")
        f.write(f"elapsed: {res['elapsed']:.3f} s\n\n")
        if res["stdout"]:
            f.write("=== STDOUT ===\n")
            f.write(res["stdout"])
            f.write("\n\n")
        if res["stderr"]:
            f.write("=== STDERR ===\n")
            f.write(res["stderr"])
            f.write("\n")


# ==============================
# Đọc danh sách repo
# ==============================
def load_repos(repo_list_path: Path):
    """
    File repo-java-binary.txt:
      - Mỗi dòng: name; url  hoặc chỉ url
      - Bỏ qua dòng trống & dòng bắt đầu bằng '#'
    """
    if not repo_list_path.is_file():
        print(f"[FATAL] Không tìm thấy file repo list: {repo_list_path}", file=sys.stderr)
        sys.exit(1)

    repos = []
    with repo_list_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ";" in line:
                name_part, url_part = line.split(";", 1)
                name = name_part.strip()
                url = url_part.strip()
            else:
                url = line
                name = url.rstrip("/").split("/")[-1]
                if name.endswith(".git"):
                    name = name[:-4]

            repos.append({"name": name, "url": url})

    if not repos:
        print(f"[FATAL] File {repo_list_path} không có repo hợp lệ.", file=sys.stderr)
        sys.exit(1)

    return repos


# ==============================
# Clone repo
# ==============================
def clone_repo(name: str, url: str, repos_dir: Path, logs_dir: Path) -> bool:
    repo_dir = repos_dir / name
    if (repo_dir / ".git").is_dir():
        print("  -> Repo đã tồn tại, bỏ qua bước clone.")
        return True

    repos_dir.mkdir(parents=True, exist_ok=True)
    print(f"  -> Cloning vào {repo_dir} ...")
    cmd = ["git", "clone", "--depth", "1", url, str(repo_dir)]
    res = run_cmd(cmd, cwd=repos_dir)
    write_log(logs_dir / f"{name}__git_clone.log", cmd, res)

    if not res["ok"]:
        print(f"     - Clone FAILED (exit={res['exit_code']}, {res['elapsed']:.2f}s)")
        return False

    return True


# ==============================
# Build Java artifact (JAR/WAR)
# ==============================
def build_java_artifact(repo_name: str, repo_dir: Path, artifacts_dir: Path, logs_dir: Path):
    """
    Build bằng Maven/mvnw -> lấy file .jar/.war mới nhất trong target/
    """
    log_file = logs_dir / f"{repo_name}__java_build.log"
    log_prefix = f"[BUILD][java][{repo_name}]"

    mvnw = repo_dir / "mvnw"
    if mvnw.exists():
        # Đảm bảo mvnw có quyền execute
        try:
            mode = mvnw.stat().st_mode
            mvnw.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except PermissionError:
            # Nếu chmod fail (ví dụ FS read-only) thì vẫn cứ thử chạy
            pass
        cmd = ["./mvnw", "-q", "-DskipTests", "clean", "package"]
    else:
        cmd = ["mvn", "-q", "-DskipTests", "clean", "package"]

    res = run_cmd(cmd, cwd=repo_dir)
    write_log(log_file, cmd, res)

    if not res["ok"]:
        print(f"    {log_prefix} FAILED (exit={res['exit_code']}, {res['elapsed']:.2f}s)")
        return None, res["elapsed"], False

    target_dir = repo_dir / "target"
    artifacts = list(target_dir.glob("*.jar")) + list(target_dir.glob("*.war"))
    artifacts = sorted(artifacts, key=lambda p: p.stat().st_mtime, reverse=True)

    if not artifacts:
        print(f"    {log_prefix} Không tìm thấy file .jar/.war trong target/")
        return None, res["elapsed"], False

    artifact_src = artifacts[0]
    dst_dir = artifacts_dir / repo_name
    dst_dir.mkdir(parents=True, exist_ok=True)
    artifact_dst = dst_dir / artifact_src.name
    shutil.copy2(artifact_src, artifact_dst)

    print(f"    {log_prefix} OK -> {artifact_dst.name} ({res['elapsed']:.2f}s)")
    return artifact_dst, res["elapsed"], True


# ==============================
# Sinh SBOM cho JAR/WAR
# ==============================
def gen_sbom_syft(artifact_path: Path, sbom_path: Path, logs_dir: Path, repo_name: str):
    cmd = [
        "syft",
        str(artifact_path),
        "--output",
        f"cyclonedx-json={sbom_path}",
    ]
    res = run_cmd(cmd)
    write_log(logs_dir / f"{repo_name}__syft.log", cmd, res)
    return res


def gen_sbom_trivy(artifact_path: Path, sbom_path: Path, logs_dir: Path, repo_name: str):
    env = os.environ.copy()
    env.setdefault("TRIVY_NO_PROGRESS", "1")
    cmd = [
        "trivy",
        "fs",
        str(artifact_path),
        "--format",
        "cyclonedx",
        "--output",
        str(sbom_path),
    ]
    res = run_cmd(cmd, env=env)
    write_log(logs_dir / f"{repo_name}__trivy.log", cmd, res)
    return res


def gen_sbom_cdxgen(artifact_path: Path, sbom_path: Path, logs_dir: Path, repo_name: str):
    cmd = [
        "cdxgen",
        "-t",
        "java",
        "-o",
        str(sbom_path),
        str(artifact_path),
    ]
    res = run_cmd(cmd)
    write_log(logs_dir / f"{repo_name}__cdxgen.log", cmd, res)
    return res


# ==============================
# Fallback: Đếm components trong CycloneDX
# ==============================
def count_components_in_cyclonedx(sbom_path: Path):
    try:
        with sbom_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    components = None
    if isinstance(data, dict):
        if isinstance(data.get("components"), list):
            components = data["components"]
        elif isinstance(data.get("bom"), dict) and isinstance(data["bom"].get("components"), list):
            components = data["bom"]["components"]

    if components is None:
        return None
    return len(components)


# ==============================
# Parse sbomqs --profile ntia
# ==============================
def parse_sbomqs_profile_ntia(stdout: str):
    """
    Parse từ output dạng:
      SBOM Quality Score: 8.5/10.0  Grade: B Components: 224 ...
    Trả về (score, grade, num_components)
    """
    if not stdout:
        return None, None, None

    line = None
    for l in stdout.splitlines():
        if "SBOM Quality Score" in l:
            line = l
            break
    if not line:
        lines = stdout.strip().splitlines()
        if not lines:
            return None, None, None
        line = lines[-1]

    m_score = re.search(r"SBOM Quality Score:\s*([\d.]+)/10\.0", line)
    score = float(m_score.group(1)) if m_score else None

    m_grade = re.search(r"Grade:\s*([A-F][+-]?)", line)
    grade = m_grade.group(1) if m_grade else None

    m_comp = re.search(r"Components:\s*(\d+)", line)
    num_components = int(m_comp.group(1)) if m_comp else None

    return score, grade, num_components


def score_sbom_ntia(sbom_path: Path, logs_dir: Path, repo_name: str, tool: str):
    cmd = [
        "sbomqs",
        "score",
        "--profile",
        "ntia",
        str(sbom_path),
    ]
    res = run_cmd(cmd)
    log_name = f"sbomqs__{repo_name}__{tool}.log"
    write_log(logs_dir / log_name, cmd, res)

    if not res["ok"]:
        print(f"      -> [ERROR] sbomqs failed (exit={res['exit_code']})", file=sys.stderr)
        return None, None, None, res

    score, grade, num_components = parse_sbomqs_profile_ntia(res["stdout"])
    if score is None:
        print("      -> [WARN] Không parse được điểm sbomqs, xem log để debug", file=sys.stderr)
    else:
        print(f"      -> sbomqs NTIA: score={score}, grade={grade}, components={num_components}")
    return score, grade, num_components, res


# ==============================
# Main
# ==============================
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark SBOM (Syft, Trivy, Cdxgen) trên các JAR/WAR Java (binary), "
            "chấm điểm sbomqs --profile ntia."
        )
    )
    parser.add_argument(
        "--repo-list",
        default=DEFAULT_REPO_LIST,
        help=f"File chứa danh sách repo (mặc định: {DEFAULT_REPO_LIST})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"File CSV kết quả (mặc định: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    repo_list_path = base_dir / args.repo_list
    output_csv = base_dir / args.output

    # Tách namespace riêng cho binary Java (tránh đụng với benchmark source)
    repos_dir = base_dir / "repos" / "java"
    artifacts_dir = base_dir / "artifacts" / "java"
    sboms_dir = base_dir / "sboms" / "java"
    logs_dir = base_dir / "logs" / "java"

    print(f"[INFO] Base dir        : {base_dir}")
    print(f"[INFO] Repo list file  : {repo_list_path}")
    print(f"[INFO] Output CSV      : {output_csv}")
    print(f"[INFO] Repos dir       : {repos_dir}")
    print(f"[INFO] Artifacts dir   : {artifacts_dir}")
    print(f"[INFO] SBOMs dir       : {sboms_dir}")
    print(f"[INFO] Logs dir        : {logs_dir}")
    print()

    check_tools()
    repos = load_repos(repo_list_path)

    repos_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    sboms_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "repo_name",
        "tool",
        "gen_elapsed_sec",
        "ntia_score",
        "grade",
        "num_of_component",
    ]

    with output_csv.open("w", newline="", encoding="utf-8") as fcsv:
        writer = csv.DictWriter(fcsv, fieldnames=fieldnames)
        writer.writeheader()

        total = len(repos)
        for idx, repo in enumerate(repos, start=1):
            name = repo["name"]
            url = repo["url"]

            print("=" * 80)
            print(f"[{idx}/{total}] Repo: {name} ({url})")

            # Clone
            ok_clone = clone_repo(name, url, repos_dir, logs_dir)
            if not ok_clone:
                print("  -> Bỏ qua repo do clone thất bại.")
                for tool in TOOLS:
                    writer.writerow(
                        {
                            "repo_name": name,
                            "tool": tool,
                            "gen_elapsed_sec": "",
                            "ntia_score": "",
                            "grade": "",
                            "num_of_component": "",
                        }
                    )
                continue

            repo_dir = repos_dir / name

            # Build artifact (jar/war)
            artifact_path, build_elapsed, ok_build = build_java_artifact(
                name, repo_dir, artifacts_dir, logs_dir
            )

            if not ok_build or artifact_path is None:
                print("  -> Không có artifact, bỏ qua phần SBOM cho repo này.")
                for tool in TOOLS:
                    writer.writerow(
                        {
                            "repo_name": name,
                            "tool": tool,
                            "gen_elapsed_sec": "",
                            "ntia_score": "",
                            "grade": "",
                            "num_of_component": "",
                        }
                    )
                continue

            # Sinh SBOM & chấm điểm
            for tool in TOOLS:
                print(f"  -> Tool = {tool}")
                sbom_path = sboms_dir / f"{name}.{tool}.cdx.json"

                if tool == "syft":
                    res_gen = gen_sbom_syft(artifact_path, sbom_path, logs_dir, name)
                elif tool == "trivy":
                    res_gen = gen_sbom_trivy(artifact_path, sbom_path, logs_dir, name)
                else:
                    res_gen = gen_sbom_cdxgen(artifact_path, sbom_path, logs_dir, name)

                print(
                    f"     - Gen SBOM: {'OK' if res_gen['ok'] else 'FAILED'} "
                    f"({res_gen['elapsed']:.2f}s, exit={res_gen['exit_code']})"
                )

                gen_elapsed_sec = f"{res_gen['elapsed']:.3f}" if res_gen["ok"] else ""
                ntia_score = ""
                grade = ""
                num_components = ""

                if res_gen["ok"] and sbom_path.is_file():
                    score, g, comps, res_score = score_sbom_ntia(
                        sbom_path, logs_dir, name, tool
                    )
                    if score is not None:
                        ntia_score = f"{score:.4f}"
                    if g is not None:
                        grade = g
                    if comps is not None:
                        num_components = comps
                    else:
                        num = count_components_in_cyclonedx(sbom_path)
                        if num is not None:
                            num_components = num
                else:
                    print("     - Bỏ qua sbomqs vì gen SBOM thất bại hoặc file không tồn tại.")

                writer.writerow(
                    {
                        "repo_name": name,
                        "tool": tool,
                        "gen_elapsed_sec": gen_elapsed_sec,
                        "ntia_score": ntia_score,
                        "grade": grade,
                        "num_of_component": num_components,
                    }
                )

    print()
    print(f"[DONE] Đã ghi kết quả vào: {output_csv}")


if __name__ == "__main__":
    main()
