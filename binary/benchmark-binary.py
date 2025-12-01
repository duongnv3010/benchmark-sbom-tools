#!/usr/bin/env python3
import argparse
import csv
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

TOOLS = ["syft", "trivy", "cdxgen"]


# -----------------------------
# Helper: run command
# -----------------------------
def run_cmd(cmd, cwd=None):
    """
    Chạy lệnh, trả về (exit_code, elapsed_sec, stdout, stderr)
    """
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        elapsed = time.time() - start
        return proc.returncode, elapsed, proc.stdout, proc.stderr
    except FileNotFoundError as e:
        elapsed = time.time() - start
        return 127, elapsed, "", str(e)


def write_log(log_path: Path, cmd, exit_code, stdout, stderr):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8", errors="ignore") as f:
        f.write("CMD: " + " ".join(cmd) + "\n")
        f.write(f"EXIT_CODE: {exit_code}\n\n")
        if stdout:
            f.write("==== STDOUT ====\n")
            f.write(stdout)
            f.write("\n\n")
        if stderr:
            f.write("==== STDERR ====\n")
            f.write(stderr)
            f.write("\n")


# -----------------------------
# Repo list parsing
# -----------------------------
def load_repo_list(path: Path):
    """
    File repo-java-binary.txt:
      - Mỗi dòng: name; url   hoặc   chỉ url
      - Bỏ qua dòng trống & dòng bắt đầu bằng '#'
    """
    repos = []
    for line in path.read_text(encoding="utf-8").splitlines():
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
    return repos


def clone_repo(name: str, url: str, repos_dir: Path, logs_dir: Path) -> bool:
    repo_dir = repos_dir / name
    if (repo_dir / ".git").is_dir():
        print(f"  -> Repo đã tồn tại, bỏ qua bước clone.")
        return True

    repos_dir.mkdir(parents=True, exist_ok=True)
    print(f"  -> Cloning vào {repo_dir} ...")
    cmd = ["git", "clone", "--depth", "1", url, str(repo_dir)]
    exit_code, elapsed, out, err = run_cmd(cmd, cwd=repos_dir)
    write_log(logs_dir / f"{name}__git_clone.log", cmd, exit_code, out, err)

    if exit_code != 0:
        print(f"     - Clone FAILED (exit={exit_code}, {elapsed:.2f}s)")
        return False

    return True


# -----------------------------
# Build Java artifact (jar/war)
# -----------------------------
def build_java_artifact(
    repo_name: str,
    repo_dir: Path,
    artifacts_dir: Path,
    logs_dir: Path,
):
    """
    Build bằng Maven/mvnw -> lấy jar/war mới nhất trong target/
    """
    log_file = logs_dir / f"java-{repo_name}-build.log"
    log_prefix = f"[BUILD][java][{repo_name}]"

    mvnw = repo_dir / "mvnw"
    if mvnw.exists():
        # Đảm bảo mvnw có quyền execute
        try:
            mode = mvnw.stat().st_mode
            mvnw.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except PermissionError:
            # Nếu chmod bị cấm thì vẫn thử chạy, có thể đã đủ quyền rồi
            pass
        cmd = ["./mvnw", "-q", "-DskipTests", "package"]
    else:
        cmd = ["mvn", "-q", "-DskipTests", "package"]

    exit_code, elapsed, out, err = run_cmd(cmd, cwd=repo_dir)
    write_log(log_file, cmd, exit_code, out, err)

    if exit_code != 0:
        print(f"    {log_prefix} FAILED (exit={exit_code}, {elapsed:.2f}s)")
        return None, elapsed, False

    target_dir = repo_dir / "target"
    # Ưu tiên .jar, nhưng nếu có .war thì cũng quét luôn
    artifacts = list(target_dir.glob("*.jar")) + list(target_dir.glob("*.war"))
    artifacts = sorted(artifacts, key=lambda p: p.stat().st_mtime, reverse=True)

    if not artifacts:
        print(f"    {log_prefix} Không tìm thấy file .jar/.war trong target/")
        return None, elapsed, False

    artifact_src = artifacts[0]
    dst_dir = artifacts_dir / repo_name
    dst_dir.mkdir(parents=True, exist_ok=True)
    artifact_dst = dst_dir / artifact_src.name
    shutil.copy2(artifact_src, artifact_dst)

    print(f"    {log_prefix} OK -> {artifact_dst.name} ({elapsed:.2f}s)")
    return artifact_dst, elapsed, True


# -----------------------------
# Generate SBOM
# -----------------------------
def generate_sbom(tool: str, repo_name: str, artifact_path: Path, sboms_dir: Path, logs_dir: Path):
    tool = tool.lower()
    sboms_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    sbom_file = sboms_dir / f"java-{repo_name}-{tool}-artifact.cdx.json"
    log_file = logs_dir / f"java-{repo_name}-{tool}-gen.log"

    if tool == "syft":
        cmd = ["syft", str(artifact_path), "--output", f"cyclonedx-json={sbom_file}"]
    elif tool == "trivy":
        cmd = ["trivy", "fs", "--format", "cyclonedx", "--output", str(sbom_file), str(artifact_path)]
    elif tool == "cdxgen":
        cmd = ["cdxgen", "-t", "java", "-o", str(sbom_file), str(artifact_path)]
    else:
        raise ValueError(f"Unknown tool: {tool}")

    exit_code, elapsed, out, err = run_cmd(cmd)
    write_log(log_file, cmd, exit_code, out, err)

    if exit_code != 0:
        print(f"      -> {tool}: FAILED (exit={exit_code}, {elapsed:.2f}s)")
        return None, elapsed, False

    if not sbom_file.exists():
        print(f"      -> {tool}: EXIT 0 nhưng không thấy file SBOM: {sbom_file}")
        return None, elapsed, False

    print(f"      -> {tool}: SBOM OK ({elapsed:.2f}s)")
    return sbom_file, elapsed, True


# -----------------------------
# sbomqs scoring (NTIA profile)
# -----------------------------
SBOMQS_RE = re.compile(
    r"SBOM Quality Score:\s*([0-9.]+)/10\.0\s+Grade:\s*([A-F][+\-]?)\s+Components:\s*([0-9]+)",
    re.IGNORECASE,
)


def score_sbom_ntia(repo_name: str, tool: str, sbom_path: Path, logs_dir: Path):
    log_file = logs_dir / f"java-{repo_name}-{tool}-sbomqs.log"
    cmd = ["sbomqs", "score", "--profile", "ntia", str(sbom_path)]

    exit_code, elapsed, out, err = run_cmd(cmd)
    write_log(log_file, cmd, exit_code, out, err)

    combined = (out or "") + "\n" + (err or "")
    m = SBOMQS_RE.search(combined)

    if not m:
        print(f"      -> sbomqs NTIA: FAILED (exit={exit_code}, không parse được điểm)")
        return "", "", "", elapsed, exit_code

    score, grade, comps = m.groups()
    print(
        f"      -> sbomqs NTIA: score={score}, grade={grade}, components={comps} "
        f"({elapsed:.2f}s, exit={exit_code})"
    )
    return score, grade, comps, elapsed, exit_code


# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Benchmark SBOM tools (Syft, Trivy, Cdxgen) trên các JAR/WAR Java, chấm điểm bằng sbomqs (profile ntia).",
    )
    parser.add_argument(
        "--repo-list",
        required=True,
        help="File danh sách repo (name;url hoặc url).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="File CSV kết quả (sẽ bị ghi đè).",
    )

    args = parser.parse_args()

    base_dir = Path.cwd().resolve()
    repo_list_file = (base_dir / args.repo_list).resolve()
    if not repo_list_file.exists():
        print(f"[ERR] Không tìm thấy repo-list: {repo_list_file}")
        sys.exit(1)

    # Chỉ làm cho Java, cố định thư mục con "java"
    repos_dir = base_dir / "repos" / "java"
    artifacts_dir = base_dir / "artifacts" / "java"
    sboms_dir = base_dir / "sboms" / "java"
    logs_dir = base_dir / "logs" / "java"

    repos_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    sboms_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Base dir       : {base_dir}")
    print(f"[INFO] Repo list file : {repo_list_file}")
    print(f"[INFO] Output CSV     : {args.output}")
    print(f"[INFO] Repos dir      : {repos_dir}")
    print(f"[INFO] Artifacts dir  : {artifacts_dir}")
    print(f"[INFO] SBOMs dir      : {sboms_dir}")
    print(f"[INFO] Logs dir       : {logs_dir}")
    print()

    repos = load_repo_list(repo_list_file)
    if not repos:
        print("[ERR] Repo list rỗng?")
        sys.exit(1)

    output_path = (base_dir / args.output).resolve()
    with output_path.open("w", newline="", encoding="utf-8") as f_csv:
        writer = csv.writer(f_csv)
        # repo_name, tool, gen_elapsed_sec, ntia_score, grade, num_of_component
        writer.writerow(["repo_name", "tool", "gen_elapsed_sec", "ntia_score", "grade", "num_of_component"])

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
                # vẫn ghi 3 dòng trống để biết thất bại
                for tool in TOOLS:
                    writer.writerow([name, tool, "", "", "", ""])
                continue

            repo_dir = repos_dir / name

            # Build artifact (jar/war)
            artifact_path, build_elapsed, ok_build = build_java_artifact(
                name, repo_dir, artifacts_dir, logs_dir
            )

            if not ok_build or artifact_path is None:
                print("  -> Không có artifact, bỏ qua phần SBOM cho repo này.")
                for tool in TOOLS:
                    writer.writerow([name, tool, "", "", "", ""])
                continue

            # Sinh SBOM & chấm điểm
            for tool in TOOLS:
                print(f"  -> Tool = {tool}")
                sbom_path, gen_elapsed, gen_ok = generate_sbom(
                    tool, name, artifact_path, sboms_dir, logs_dir
                )

                ntia_score = ""
                grade = ""
                num_components = ""

                if gen_ok and sbom_path is not None:
                    score, grd, comps, score_elapsed, score_exit = score_sbom_ntia(
                        name, tool, sbom_path, logs_dir
                    )
                    ntia_score = score
                    grade = grd
                    num_components = comps
                else:
                    print(f"      -> Bỏ qua sbomqs do không có SBOM hợp lệ từ {tool}")

                writer.writerow(
                    [
                        name,
                        tool,
                        f"{gen_elapsed:.2f}" if gen_ok else "",
                        ntia_score,
                        grade,
                        num_components,
                    ]
                )

    print()
    print(f"[DONE] Đã ghi kết quả vào: {output_path}")


if __name__ == "__main__":
    main()
