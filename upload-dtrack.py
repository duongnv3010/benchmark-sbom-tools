#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import sys
import time
from pathlib import Path

import requests

# ==========================================
# CẤU HÌNH CẦN SỬA
# ==========================================
# VD: "http://192.168.122.140:8081"
DTRACK_URL = "http://192.168.1.1:9092"
DTRACK_API_KEY = "odt_b7jm7wA8_tSBMgcVW0jP3pUsNSvsdeIDXwuq0FMUL"
PROJECT_VERSION = "1.0"

# ==========================================
API_BASE = DTRACK_URL.rstrip("/") + "/api/v1"
HEADERS = {
    "X-Api-Key": DTRACK_API_KEY,
    "Accept": "application/json",
}

RESULT_CSV = "result-upload-dtrack.csv"


def log_info(msg: str) -> None:
    print(f"[INFO] {msg}")


def log_warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr)


def log_err(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def derive_app_and_tool(filename: str):
    """
    Từ tên file SBOM: <app-name>.<sbom-tool>.cdx.json
    → trả về (app_name, sbom_tool)
    """
    name = filename
    if name.endswith(".cdx.json"):
        name = name[:-len(".cdx.json")]
    else:
        name = name.rsplit(".", 1)[0]

    parts = name.split(".")
    if len(parts) >= 2:
        sbom_tool = parts[-1]
        app_name = ".".join(parts[:-1])
    else:
        sbom_tool = "unknown"
        app_name = name

    return app_name, sbom_tool


def make_project_name(kind: str, language: str, filename: str) -> str:
    """
    kind: 'src', 'image', 'binary'
    language: 'java' | 'python' | 'nodejs' | None
    """
    app_name, sbom_tool = derive_app_and_tool(filename)

    if kind == "src":
        if not language:
            language = "unknown"
        project_name = f"src.{language}.{app_name}.{sbom_tool}"
    elif kind == "image":
        project_name = f"image.{app_name}.{sbom_tool}"
    elif kind == "binary":
        project_name = f"binary.{app_name}.{sbom_tool}"
    else:
        project_name = f"{kind}.{app_name}.{sbom_tool}"

    return project_name


def find_sboms(base_dir: Path):
    """
    Tìm SBOM ở:
      - source-code/java/sboms/*.cdx.json
      - source-code/nodejs/sboms/*.cdx.json
      - source-code/python/sboms/*.cdx.json
      - images/sboms/*.cdx.json
      - binary/sboms/java/*.cdx.json
    """
    entries = []

    # Source code
    src_map = {
        "java": base_dir / "source-code" / "java" / "sboms",
        "nodejs": base_dir / "source-code" / "nodejs" / "sboms",
        "python": base_dir / "source-code" / "python" / "sboms",
    }
    for lang, sbom_dir in src_map.items():
        if sbom_dir.is_dir():
            for f in sorted(sbom_dir.glob("*.cdx.json")):
                project_name = make_project_name("src", lang, f.name)
                entries.append(
                    {
                        "kind": "src",
                        "language": lang,
                        "path": f,
                        "project_name": project_name,
                    }
                )
        else:
            log_warn(f"Thư mục SBOM source-code cho {lang} không tồn tại: {sbom_dir}")

    # Image
    img_dir = base_dir / "images" / "sboms"
    if img_dir.is_dir():
        for f in sorted(img_dir.glob("*.cdx.json")):
            project_name = make_project_name("image", None, f.name)
            entries.append(
                {
                    "kind": "image",
                    "language": None,
                    "path": f,
                    "project_name": project_name,
                }
            )
    else:
        log_warn(f"Thư mục SBOM image không tồn tại: {img_dir}")

    # Binary (Java)
    bin_java_dir = base_dir / "binary" / "sboms" / "java"
    if bin_java_dir.is_dir():
        for f in sorted(bin_java_dir.glob("*.cdx.json")):
            project_name = make_project_name("binary", None, f.name)
            entries.append(
                {
                    "kind": "binary",
                    "language": "java",
                    "path": f,
                    "project_name": project_name,
                }
            )
    else:
        log_warn(f"Thư mục SBOM binary/java không tồn tại: {bin_java_dir}")

    return entries


def upload_sbom(project_name: str, sbom_path: Path) -> (str, str):
    """
    Upload 1 SBOM: trả về (status, error_msg)
      - status: "ok" hoặc "fail"
      - error_msg: text ngắn gọn nếu fail
    """
    url = API_BASE + "/bom"
    data = {
        "autoCreate": "true",
        "projectName": project_name,
        "projectVersion": PROJECT_VERSION,
    }

    log_info(f"  -> Upload SBOM: {sbom_path} => project='{project_name}', version='{PROJECT_VERSION}'")

    try:
        with sbom_path.open("rb") as f:
            files = {
                "bom": (sbom_path.name, f, "application/json"),
            }
            resp = requests.post(url, headers=HEADERS, data=data, files=files, timeout=120)
    except Exception as e:
        msg = f"Lỗi kết nối: {e}"
        log_err(f"  -> {msg}")
        return "fail", msg

    if 200 <= resp.status_code < 300:
        log_info(f"  -> Upload OK (HTTP {resp.status_code})")
        return "ok", ""
    else:
        msg = f"HTTP {resp.status_code}: {resp.text[:200]}"
        log_err(f"  -> Upload FAIL: {msg}")
        return "fail", msg


def main():
    base_dir = Path(__file__).resolve().parent
    log_info(f"D-Track URL : {DTRACK_URL}")
    log_info(f"API base    : {API_BASE}")
    log_info(f"Project version mặc định: {PROJECT_VERSION}")
    log_info(f"Thư mục gốc benchmark  : {base_dir}")

    entries = find_sboms(base_dir)
    if not entries:
        log_warn("Không tìm thấy SBOM nào. Kiểm tra lại cấu trúc thư mục và tên file (*.cdx.json).")
        sys.exit(1)

    log_info(f"Tổng số SBOM tìm được: {len(entries)}\n")

    csv_path = base_dir / RESULT_CSV
    fieldnames = [
        "Name of project",
        "Status",           # ok/fail (upload)
        "Risk Score",
        "Total Vuln",
        "Vuln (Critical)",
        "Vuln (High)",
        "Vuln (Medium)",
        "Vuln (Low)",
        "Vuln (Unassign)",
    ]

    rows = []

    for idx, entry in enumerate(entries, start=1):
        project_name = entry["project_name"]
        sbom_path = entry["path"]

        print("=" * 80)
        log_info(f"[{idx}/{len(entries)}] SBOM: {sbom_path}")
        log_info(f"  kind={entry['kind']}, language={entry['language']}, project='{project_name}'")

        status, err = upload_sbom(project_name, sbom_path)

        row = {
            "Name of project": project_name,
            "Status": status,
            "Risk Score": "",
            "Total Vuln": "",
            "Vuln (Critical)": "",
            "Vuln (High)": "",
            "Vuln (Medium)": "",
            "Vuln (Low)": "",
            "Vuln (Unassign)": "",
        }
        rows.append(row)

        # Delay 2s giữa mỗi project để tránh overload D-Track
        time.sleep(2)

    # Ghi CSV (ghi đè)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print("=" * 80)
    log_info(f"Đã ghi kết quả upload vào: {csv_path}")
    log_info("Lưu ý: metrics chưa có trong file này. Hãy chạy metrics_dtrack.py để cập nhật.")


if __name__ == "__main__":
    main()
