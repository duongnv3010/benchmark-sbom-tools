#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple

# ==============================
# Cấu hình cơ bản
# ==============================
DEFAULT_REPO_LIST = "repo-nodejs.txt"
DEFAULT_OUTPUT = "result-nodejs-3.csv"
REQUIRED_TOOLS = ["git", "syft", "trivy", "cdxgen", "sbomqs"]


# ==============================
# Hàm tiện ích
# ==============================
def check_tools():
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        print("[FATAL] Thiếu các tool sau trong PATH:", ", ".join(missing))
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


def repo_name_from_url(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name


def load_repos(repo_list_path: Path) -> List[Tuple[str, str]]:
    """
    Hỗ trợ 2 kiểu dòng:
      1) name,url
      2) url

    Dòng bắt đầu bằng '#' sẽ bị bỏ qua (comment).
    """
    if not repo_list_path.is_file():
        print(f"[FATAL] Không tìm thấy file repo list: {repo_list_path}")
        sys.exit(1)

    repos: List[Tuple[str, str]] = []
    with repo_list_path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if "," in line:
                name, url = [p.strip() for p in line.split(",", 1)]
                if not name:
                    name = repo_name_from_url(url)
            else:
                url = line
                name = repo_name_from_url(url)

            if not url:
                continue
            repos.append((name, url))

    if not repos:
        print(f"[FATAL] File {repo_list_path} không có repo hợp lệ.")
        sys.exit(1)
    return repos


def count_components_in_cyclonedx(sbom_path: Path):
    """
    Fallback: nếu sbomqs không báo Components,
    cố gắng đếm từ JSON CycloneDX.
    """
    try:
        with sbom_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    components = None
    if isinstance(data, dict):
        if isinstance(data.get("components"), list):
            components = data["components"]
        elif isinstance(data.get("bom"), dict) and isinstance(
            data["bom"].get("components"), list
        ):
            components = data["bom"]["components"]

    if components is None:
        return None
    return len(components)


# ==============================
# Sinh SBOM
# ==============================
def gen_sbom_syft(repo_dir: Path, sbom_path: Path, logs_dir: Path):
    cmd = [
        "syft",
        "dir:.",
        "-o",
        f"cyclonedx-json={sbom_path}",
    ]
    res = run_cmd(cmd, cwd=repo_dir)
    write_log(logs_dir / f"{repo_dir.name}__syft.log", cmd, res)
    return res


def gen_sbom_trivy(repo_dir: Path, sbom_path: Path, logs_dir: Path):
    env = os.environ.copy()
    env.setdefault("TRIVY_NO_PROGRESS", "1")
    cmd = [
        "trivy",
        "fs",
        ".",
        "--format",
        "cyclonedx",
        "--output",
        str(sbom_path),
    ]
    res = run_cmd(cmd, cwd=repo_dir, env=env)
    write_log(logs_dir / f"{repo_dir.name}__trivy.log", cmd, res)
    return res


def gen_sbom_cdxgen(repo_dir: Path, sbom_path: Path, logs_dir: Path):
    cmd = [
        "cdxgen",
        "-r",
        "-o",
        str(sbom_path),
        ".",
    ]
    res = run_cmd(cmd, cwd=repo_dir)
    write_log(logs_dir / f"{repo_dir.name}__cdxgen.log", cmd, res)
    return res


# ==============================
# Parse output sbomqs --profile ntia
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
        print(f"    [ERROR] sbomqs failed (exit={res['exit_code']})", file=sys.stderr)
        return None, None, None, res

    score, grade, num_components = parse_sbomqs_profile_ntia(res["stdout"])
    if score is None:
        print("    [WARN] Không parse được điểm sbomqs, xem log để debug", file=sys.stderr)
    else:
        print(
            f"    -> sbomqs NTIA: score={score}, grade={grade}, components={num_components}"
        )
    return score, grade, num_components, res


# ==============================
# Main
# ==============================
def main():
    parser = argparse.ArgumentParser(
        description="Benchmark SBOM (Syft, Trivy, Cdxgen) trên Node.js repos, chấm sbomqs --profile ntia."
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
    repos_dir = base_dir / "repos"
    sboms_dir = base_dir / "sboms"
    logs_dir = base_dir / "logs"

    print(f"[INFO] Base dir        : {base_dir}")
    print(f"[INFO] Repo list file  : {repo_list_path}")
    print(f"[INFO] Output CSV      : {output_csv}")
    print(f"[INFO] Repos dir       : {repos_dir}")
    print(f"[INFO] SBOMs dir       : {sboms_dir}")
    print(f"[INFO] Logs dir        : {logs_dir}")
    print()

    check_tools()
    repos = load_repos(repo_list_path)

    repos_dir.mkdir(parents=True, exist_ok=True)
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

        for idx, (repo_name, repo_url) in enumerate(repos, start=1):
            print("=" * 80)
            print(f"[{idx}/{len(repos)}] Repo: {repo_name} ({repo_url})")

            repo_dir = repos_dir / repo_name

            # Clone nếu chưa có
            if not repo_dir.exists():
                print(f"  -> Cloning vào {repo_dir} ...")
                cmd = ["git", "clone", "--depth", "1", repo_url, str(repo_dir)]
                res_clone = run_cmd(cmd, cwd=repos_dir)
                write_log(logs_dir / f"{repo_name}__git_clone.log", cmd, res_clone)
                if not res_clone["ok"]:
                    print("  [ERROR] Clone thất bại, bỏ qua repo này.")
                    for tool in ["syft", "trivy", "cdxgen"]:
                        writer.writerow(
                            {
                                "repo_name": repo_name,
                                "tool": tool,
                                "gen_elapsed_sec": "",
                                "ntia_score": "",
                                "grade": "",
                                "num_of_component": "",
                            }
                        )
                    continue
            else:
                print("  -> Repo đã tồn tại, bỏ qua bước clone.")

            # Cho từng tool
            for tool in ["syft", "trivy", "cdxgen"]:
                print(f"  -> Tool = {tool}")
                sbom_path = sboms_dir / f"{repo_name}.{tool}.cdx.json"

                # 1. Gen SBOM
                if tool == "syft":
                    res_gen = gen_sbom_syft(repo_dir, sbom_path, logs_dir)
                elif tool == "trivy":
                    res_gen = gen_sbom_trivy(repo_dir, sbom_path, logs_dir)
                else:
                    res_gen = gen_sbom_cdxgen(repo_dir, sbom_path, logs_dir)

                print(
                    f"     - Gen SBOM: {'OK' if res_gen['ok'] else 'FAILED'} "
                    f"({res_gen['elapsed']:.2f}s, exit={res_gen['exit_code']})"
                )

                gen_elapsed_sec = f"{res_gen['elapsed']:.3f}"
                ntia_score = ""
                grade = ""
                num_of_component = ""

                if res_gen["ok"] and sbom_path.is_file():
                    # 2. Chấm điểm sbomqs --profile ntia
                    score, g, comps, res_score = score_sbom_ntia(
                        sbom_path, logs_dir, repo_name, tool
                    )
                    if score is not None:
                        ntia_score = f"{score:.4f}"
                    if g is not None:
                        grade = g
                    if comps is not None:
                        num_of_component = comps
                    else:
                        num = count_components_in_cyclonedx(sbom_path)
                        if num is not None:
                            num_of_component = num
                else:
                    print(
                        "     - Bỏ qua sbomqs vì gen SBOM thất bại hoặc file không tồn tại."
                    )

                writer.writerow(
                    {
                        "repo_name": repo_name,
                        "tool": tool,
                        "gen_elapsed_sec": gen_elapsed_sec if res_gen["ok"] else "",
                        "ntia_score": ntia_score,
                        "grade": grade,
                        "num_of_component": num_of_component,
                    }
                )

    print()
    print(f"[DONE] Đã ghi kết quả vào: {output_csv}")


if __name__ == "__main__":
    main()
