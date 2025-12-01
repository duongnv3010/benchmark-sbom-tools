#!/usr/bin/env python3
import argparse
import csv
import os
import re
import subprocess
import sys
import time
from typing import List, Tuple, Optional


TOOLS = ["syft", "trivy", "cdxgen"]


def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> Tuple[int, float, str, str]:
    """
    Chạy lệnh và trả về (exit_code, elapsed_sec, stdout, stderr)
    """
    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, err = proc.communicate()
        elapsed = time.time() - start
        return proc.returncode, elapsed, out, err
    except FileNotFoundError as e:
        elapsed = time.time() - start
        return 127, elapsed, "", str(e)


def write_log(log_path: str, cmd: List[str], exit_code: int, stdout: str, stderr: str) -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w", encoding="utf-8", errors="ignore") as f:
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


def parse_repo_list(path: str) -> List[Tuple[str, str]]:
    repos: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # name,url
            parts = [p.strip() for p in line.split(",", 1)]
            if len(parts) != 2:
                print(f"[WARN] Bỏ qua dòng không hợp lệ trong repo list: {line}")
                continue
            name, url = parts
            repos.append((name, url))
    return repos


def clone_repo(name: str, url: str, repos_dir: str) -> bool:
    repo_dir = os.path.join(repos_dir, name)
    if os.path.isdir(os.path.join(repo_dir, ".git")):
        print(f"  -> Repo đã tồn tại, bỏ qua bước clone.")
        return True

    os.makedirs(repos_dir, exist_ok=True)
    print(f"  -> Cloning vào {repo_dir} ...")
    cmd = ["git", "clone", "--depth", "1", url, repo_dir]
    exit_code, elapsed, out, err = run_cmd(cmd)
    log_path = os.path.join(repos_dir, f"{name}__git_clone.log")
    write_log(log_path, cmd, exit_code, out, err)
    if exit_code != 0:
        print(f"    [ERROR] git clone thất bại (exit={exit_code}, {elapsed:.2f}s)")
        return False
    return True


def gen_sbom(
    tool: str,
    repo_name: str,
    repo_dir: str,
    sboms_dir: str,
    logs_dir: str,
) -> Tuple[bool, float, str]:
    """
    Sinh SBOM cho 1 repo + 1 tool.
    Trả về (success, elapsed_sec, sbom_path)
    """
    os.makedirs(sboms_dir, exist_ok=True)
    sbom_path = os.path.join(sboms_dir, f"{repo_name}.{tool}.cdx.json")

    if tool == "syft":
        # Dùng syft scan dir: giống cách bạn hay dùng cho image
        cmd = [
            "syft",
            "scan",
            f"dir:{repo_dir}",
            "-o",
            f"cyclonedx-json={sbom_path}",
        ]
    elif tool == "trivy":
        # Trivy fs, output CycloneDX
        cmd = [
            "trivy",
            "fs",
            "--format",
            "cyclonedx",
            "--output",
            sbom_path,
            repo_dir,
        ]
    elif tool == "cdxgen":
        # Cdxgen tự detect project type (Node.js)
        cmd = [
            "cdxgen",
            "-o",
            sbom_path,
            repo_dir,
        ]
    else:
        raise ValueError(f"Tool không hỗ trợ: {tool}")

    log_path = os.path.join(logs_dir, f"{repo_name}__{tool}.gen.log")
    exit_code, elapsed, out, err = run_cmd(cmd, cwd=repo_dir)
    write_log(log_path, cmd, exit_code, out, err)

    if exit_code != 0:
        print(f"     - Gen SBOM: FAILED ({elapsed:.2f}s, exit={exit_code})")
        return False, elapsed, sbom_path

    print(f"     - Gen SBOM: OK ({elapsed:.2f}s, exit={exit_code})")
    return True, elapsed, sbom_path


def parse_sbomqs_ntia(stdout: str) -> Tuple[Optional[float], Optional[str], Optional[int]]:
    """
    Parse dòng:
    SBOM Quality Score: 8.5/10.0  Grade: B Components: 224  EngineVersion: 1 File: ...
    """
    pattern = r"SBOM Quality Score:\s*([0-9.]+)/10\.0\s*Grade:\s*([A-Za-z\+\-]+)\s*Components:\s*([0-9]+)"
    m = re.search(pattern, stdout)
    if not m:
        return None, None, None
    score_str, grade, comps_str = m.groups()
    try:
        score = float(score_str)
    except ValueError:
        score = None
    try:
        num_components = int(comps_str)
    except ValueError:
        num_components = None
    return score, grade, num_components


def score_sbom_ntia(
    sbom_path: str,
    repo_name: str,
    tool: str,
    logs_dir: str,
) -> Tuple[Optional[float], Optional[str], Optional[int], int, float]:
    """
    Chấm điểm SBOM bằng sbomqs profile ntia.
    Trả về: (score, grade, num_components, exit_code, elapsed)
    """
    cmd = [
        "sbomqs",
        "score",
        "--profile",
        "ntia",
        sbom_path,
    ]
    log_path = os.path.join(logs_dir, f"{repo_name}__{tool}.sbomqs.log")

    exit_code, elapsed, out, err = run_cmd(cmd)
    write_log(log_path, cmd, exit_code, out, err)

    if exit_code != 0:
        print(f"    [ERROR] sbomqs failed (exit={exit_code})")
        return None, None, None, exit_code, elapsed

    score, grade, num_components = parse_sbomqs_ntia(out)
    if score is None:
        # Thử parse thêm từ stderr nếu cần
        score, grade, num_components = parse_sbomqs_ntia(err)

    if score is None:
        print("    [WARN] Không parse được SBOM Quality Score từ output của sbomqs.")
    else:
        print(
            f"     - sbomqs NTIA: OK (score={score}, grade={grade}, components={num_components}, {elapsed:.2f}s, exit={exit_code})"
        )
    return score, grade, num_components, exit_code, elapsed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark SBOM tools (Syft/Trivy/cdxgen) trên các repo Node.js dùng sbomqs profile ntia"
    )
    parser.add_argument(
        "--repo-list",
        default="repo-nodejs.txt",
        help="File danh sách repo (mặc định: repo-nodejs.txt)",
    )
    parser.add_argument(
        "--output",
        default="result-nodejs.csv",
        help="File CSV output (mặc định: result-nodejs.csv)",
    )
    parser.add_argument(
        "--base-dir",
        default=".",
        help="Thư mục gốc chạy benchmark (mặc định: .)",
    )

    args = parser.parse_args()

    base_dir = os.path.abspath(args.base_dir)
    repo_list_path = os.path.abspath(os.path.join(base_dir, args.repo_list))
    output_csv = os.path.abspath(os.path.join(base_dir, args.output))

    repos_dir = os.path.join(base_dir, "repos")
    sboms_dir = os.path.join(base_dir, "sboms")
    logs_dir = os.path.join(base_dir, "logs")

    os.makedirs(repos_dir, exist_ok=True)
    os.makedirs(sboms_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    print(f"[INFO] Base dir        : {base_dir}")
    print(f"[INFO] Repo list file  : {repo_list_path}")
    print(f"[INFO] Output CSV      : {output_csv}")
    print(f"[INFO] Repos dir       : {repos_dir}")
    print(f"[INFO] SBOMs dir       : {sboms_dir}")
    print(f"[INFO] Logs dir        : {logs_dir}")
    print()

    if not os.path.isfile(repo_list_path):
        print(f"[ERROR] Không tìm thấy file repo list: {repo_list_path}")
        sys.exit(1)

    repos = parse_repo_list(repo_list_path)
    if not repos:
        print("[ERROR] Repo list trống hoặc không hợp lệ.")
        sys.exit(1)

    # Chuẩn bị CSV
    fieldnames = [
        "repo_name",
        "tool",
        "gen_elapsed_sec",
        "ntia_score",
        "grade",
        "num_of_component",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        total = len(repos)
        for idx, (name, url) in enumerate(repos, start=1):
            print("=" * 80)
            print(f"[{idx}/{total}] Repo: {name} ({url})")

            # Clone repo
            ok = clone_repo(name, url, repos_dir)
            if not ok:
                print("  -> Bỏ qua repo do clone thất bại.")
                continue

            repo_dir = os.path.join(repos_dir, name)

            for tool in TOOLS:
                print(f"  -> Tool = {tool}")
                success, gen_elapsed, sbom_path = gen_sbom(
                    tool, name, repo_dir, sboms_dir, logs_dir
                )

                if not success or not os.path.isfile(sbom_path):
                    # Ghi dòng CSV nhưng không có điểm
                    writer.writerow(
                        {
                            "repo_name": name,
                            "tool": tool,
                            "gen_elapsed_sec": f"{gen_elapsed:.2f}",
                            "ntia_score": "",
                            "grade": "",
                            "num_of_component": "",
                        }
                    )
                    continue

                # Chấm điểm bằng sbomqs profile ntia
                score, grade, num_components, exit_code, sbomqs_elapsed = score_sbom_ntia(
                    sbom_path, name, tool, logs_dir
                )

                if score is None:
                    # Không parse được điểm
                    writer.writerow(
                        {
                            "repo_name": name,
                            "tool": tool,
                            "gen_elapsed_sec": f"{gen_elapsed:.2f}",
                            "ntia_score": "",
                            "grade": "",
                            "num_of_component": "",
                        }
                    )
                else:
                    writer.writerow(
                        {
                            "repo_name": name,
                            "tool": tool,
                            "gen_elapsed_sec": f"{gen_elapsed:.2f}",
                            "ntia_score": f"{score}",
                            "grade": grade,
                            "num_of_component": num_components,
                        }
                    )

    print("=" * 80)
    print(f"[DONE] Benchmark hoàn thành. Kết quả nằm trong: {output_csv}")


if __name__ == "__main__":
    main()
