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


# ---------------------------
# Helpers
# ---------------------------
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


def parse_image_list(path: str) -> List[str]:
    """
    images.txt: mỗi dòng 1 image ref, ví dụ:
      nginx:1.27
      192.168.122.1:8890/duong3010/be-image:v3.25
    """
    images: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            images.append(line)
    return images


def sanitize_image_name(image: str) -> str:
    """
    Dùng cho tên file: thay / -> __, : -> _
    """
    name = image.replace("/", "__")
    name = name.replace(":", "_")
    return name


# ---------------------------
# SBOM generation
# ---------------------------
def gen_sbom(
    tool: str,
    image: str,
    image_id: str,
    sboms_dir: str,
    logs_dir: str,
) -> Tuple[bool, float, str]:
    """
    Sinh SBOM cho 1 image + 1 tool.
    Trả về (success, elapsed_sec, sbom_path)
    """
    os.makedirs(sboms_dir, exist_ok=True)
    sbom_path = os.path.join(sboms_dir, f"{image_id}.{tool}.cdx.json")

    if tool == "syft":
        cmd = [
            "syft",
            "scan",
            image,
            "-o",
            f"cyclonedx-json={sbom_path}",
        ]
    elif tool == "trivy":
        cmd = [
            "trivy",
            "image",
            "--quiet",
            "--format",
            "cyclonedx",
            "--output",
            sbom_path,
            image,
        ]
    elif tool == "cdxgen":
        cmd = [
            "cdxgen",
            "-t",
            "docker",
            "-o",
            sbom_path,
            image,
        ]
    else:
        raise ValueError(f"Tool không hỗ trợ: {tool}")

    log_path = os.path.join(logs_dir, f"{image_id}__{tool}.gen.log")
    exit_code, elapsed, out, err = run_cmd(cmd)
    write_log(log_path, cmd, exit_code, out, err)

    if exit_code != 0:
        print(f"     - Gen SBOM: FAILED ({elapsed:.2f}s, exit={exit_code})")
        return False, elapsed, sbom_path

    print(f"     - Gen SBOM: OK ({elapsed:.2f}s, exit={exit_code})")
    return True, elapsed, sbom_path


# ---------------------------
# sbomqs parsing
# ---------------------------
def parse_sbomqs_ntia(stdout: str) -> Tuple[Optional[float], Optional[str], Optional[int]]:
    """
    Parse dòng:
    SBOM Quality Score: 8.5/10.0  Grade: B Components: 224 ...
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
    image_id: str,
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
    log_path = os.path.join(logs_dir, f"{image_id}__{tool}.sbomqs.log")

    exit_code, elapsed, out, err = run_cmd(cmd)
    write_log(log_path, cmd, exit_code, out, err)

    if exit_code != 0:
        print(f"    [ERROR] sbomqs failed (exit={exit_code})")
        return None, None, None, exit_code, elapsed

    score, grade, num_components = parse_sbomqs_ntia(out)
    if score is None:
        # thử luôn stderr phòng trường hợp output bị in sang đó
        score, grade, num_components = parse_sbomqs_ntia(err)

    if score is None:
        print("    [WARN] Không parse được SBOM Quality Score từ output của sbomqs.")
    else:
        print(
            f"     - sbomqs NTIA: OK (score={score}, grade={grade}, components={num_components}, "
            f"{elapsed:.2f}s, exit={exit_code})"
        )
    return score, grade, num_components, exit_code, elapsed


# ---------------------------
# Main
# ---------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark SBOM tools (Syft/Trivy/cdxgen) trên list image, dùng sbomqs profile ntia"
    )
    parser.add_argument(
        "--image-list",
        default="images.txt",
        help="File danh sách image (mặc định: images.txt)",
    )
    parser.add_argument(
        "--output",
        default="result-images-2.csv",
        help="File CSV output (mặc định: result-images-2.csv)",
    )
    parser.add_argument(
        "--base-dir",
        default=".",
        help="Thư mục gốc chạy benchmark (mặc định: .)",
    )

    args = parser.parse_args()

    base_dir = os.path.abspath(args.base_dir)
    image_list_path = os.path.abspath(os.path.join(base_dir, args.image_list))
    output_csv = os.path.abspath(os.path.join(base_dir, args.output))

    sboms_dir = os.path.join(base_dir, "sboms")
    logs_dir = os.path.join(base_dir, "logs")

    os.makedirs(sboms_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    print(f"[INFO] Base dir        : {base_dir}")
    print(f"[INFO] Image list file : {image_list_path}")
    print(f"[INFO] Output CSV      : {output_csv}")
    print(f"[INFO] SBOMs dir       : {sboms_dir}")
    print(f"[INFO] Logs dir        : {logs_dir}")
    print()

    if not os.path.isfile(image_list_path):
        print(f"[ERROR] Không tìm thấy file image list: {image_list_path}")
        sys.exit(1)

    images = parse_image_list(image_list_path)
    if not images:
        print("[ERROR] Image list trống hoặc không hợp lệ.")
        sys.exit(1)

    fieldnames = [
        "image",
        "tool",
        "gen_elapsed_sec",
        "ntia_score",
        "grade",
        "num_of_component",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        total = len(images)
        for idx, image in enumerate(images, start=1):
            image_id = sanitize_image_name(image)
            print("=" * 80)
            print(f"[{idx}/{total}] Image: {image}")

            for tool in TOOLS:
                print(f"  -> Tool = {tool}")
                success, gen_elapsed, sbom_path = gen_sbom(
                    tool, image, image_id, sboms_dir, logs_dir
                )

                gen_elapsed_str = f"{gen_elapsed:.2f}"
                ntia_score = ""
                grade = ""
                num_components = ""

                if success and os.path.isfile(sbom_path):
                    score, g, comps, exit_code, sbomqs_elapsed = score_sbom_ntia(
                        sbom_path, image_id, tool, logs_dir
                    )
                    if score is not None:
                        ntia_score = f"{score}"
                    if g is not None:
                        grade = g
                    if comps is not None:
                        num_components = comps
                else:
                    print("     - Bỏ qua sbomqs vì gen SBOM thất bại hoặc file không tồn tại.")

                writer.writerow(
                    {
                        "image": image,
                        "tool": tool,
                        "gen_elapsed_sec": gen_elapsed_str if success else "",
                        "ntia_score": ntia_score,
                        "grade": grade,
                        "num_of_component": num_components,
                    }
                )

    print("=" * 80)
    print(f"[DONE] Benchmark images hoàn thành. Kết quả nằm trong: {output_csv}")


if __name__ == "__main__":
    main()
