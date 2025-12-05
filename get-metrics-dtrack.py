#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import sys
from pathlib import Path

import requests

# ==========================================
# CẤU HÌNH CẦN SỬA
# ==========================================
DTRACK_URL = "http://192.168.1.1:9092"   # VD: http://192.168.122.140:8081
DTRACK_API_KEY = "odt_b7jm7wA8_tSBMgcVW0jP3pUsNSvsdeIDXwuq0FMUL"
PROJECT_VERSION = "1.0"

# ==========================================
API_BASE = DTRACK_URL.rstrip("/") + "/api/v1"
HEADERS = {
    "X-Api-Key": DTRACK_API_KEY,
    "Accept": "application/json",
}

RESULT_CSV = "result-upload-dtrack-2.csv"


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


def lookup_project_uuid(project_name: str, project_version: str):
    url = API_BASE + "/project/lookup"
    params = {
        "name": project_name,
        "version": project_version,
    }

    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=60)
    except Exception as e:
        log_err(f"  -> Lỗi khi lookup project '{project_name}': {e}")
        return None

    if resp.status_code == 404:
        log_warn(f"  -> Project '{project_name}' (v={project_version}) chưa tìm thấy (HTTP 404)")
        return None

    if not (200 <= resp.status_code < 300):
        log_err(f"  -> Lookup project FAIL (HTTP {resp.status_code}): {resp.text[:200]}")
        return None

    try:
        data = resp.json()
    except Exception as e:
        log_err(f"  -> Không parse được JSON khi lookup project: {e}")
        return None

    uuid = data.get("uuid")
    if not uuid:
        log_err("  -> JSON không có trường 'uuid'")
        return None

    log_info(f"  -> Project UUID: {uuid}")
    return uuid


def get_metrics(uuid: str):
    """
    GET /api/v1/metrics/project/{uuid}/current
    Trả về dict metrics hoặc None nếu chưa có / lỗi.
    """
    url = API_BASE + f"/metrics/project/{uuid}/current"

    try:
        resp = requests.get(url, headers=HEADERS, timeout=120)
    except Exception as e:
        log_warn(f"  -> Lỗi khi GET metrics: {e}")
        return None

    if resp.status_code == 404:
        log_warn("  -> Metrics 404 (chưa có metrics cho project này?)")
        return None

    if not (200 <= resp.status_code < 300):
        log_warn(f"  -> GET metrics FAIL (HTTP {resp.status_code}): {resp.text[:200]}")
        return None

    if not resp.text or not resp.text.strip():
        log_warn("  -> Metrics trả về body rỗng (HTTP 200)")
        return None

    try:
        data = resp.json()
    except Exception as e:
        log_warn(f"  -> Không parse được JSON metrics: {e}")
        return None

    metrics = {
        "risk_score": data.get("inheritedRiskScore"),
        "total_vuln": data.get("vulnerabilities"),
        "critical": data.get("critical"),
        "high": data.get("high"),
        "medium": data.get("medium"),
        "low": data.get("low"),
        "unassigned": data.get("unassigned"),
    }

    log_info(
        "  -> Metrics: "
        f"RiskScore={metrics['risk_score']} | "
        f"Vuln total={metrics['total_vuln']} | "
        f"C={metrics['critical']} H={metrics['high']} "
        f"M={metrics['medium']} L={metrics['low']} U={metrics['unassigned']}"
    )

    return metrics


def main():
    base_dir = Path(__file__).resolve().parent
    log_info(f"D-Track URL : {DTRACK_URL}")
    log_info(f"API base    : {API_BASE}")
    log_info(f"Project version: {PROJECT_VERSION}")
    log_info(f"Thư mục gốc benchmark: {base_dir}")

    entries = find_sboms(base_dir)
    if not entries:
        log_warn("Không tìm thấy SBOM nào. Kiểm tra lại cấu trúc thư mục.")
        sys.exit(1)

    log_info(f"Tổng số SBOM (project) sẽ cố đọc metrics: {len(entries)}")

    # Đọc file CSV hiện có (nếu có) để giữ lại Status
    csv_path = base_dir / RESULT_CSV
    existing_rows = {}

    if csv_path.exists():
        log_info(f"Đọc file CSV hiện tại: {csv_path}")
        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("Name of project")
                if not name:
                    continue
                existing_rows[name] = row
    else:
        log_warn("Chưa có file result-upload-dtrack.csv, sẽ tạo mới.")

    # Chuẩn bị metrics mới
    metrics_by_project = {}

    for idx, entry in enumerate(entries, start=1):
        project_name = entry["project_name"]
        print("=" * 80)
        log_info(f"[{idx}/{len(entries)}] Project: {project_name}")

        uuid = lookup_project_uuid(project_name, PROJECT_VERSION)
        if not uuid:
            log_warn("  -> Không lấy được UUID, bỏ qua metrics cho project này.")
            metrics_by_project[project_name] = None
            continue

        metrics = get_metrics(uuid)
        if metrics is None:
            log_warn("  -> Chưa có metrics cho project này (hoặc lỗi), giữ nguyên hoặc để trống.")
        metrics_by_project[project_name] = metrics

    # Gom dữ liệu để ghi CSV
    fieldnames = [
        "Name of project",
        "Status",
        "Risk Score",
        "Total Vuln",
        "Vuln (Critical)",
        "Vuln (High)",
        "Vuln (Medium)",
        "Vuln (Low)",
        "Vuln (Unassign)",
    ]

    # Update rows với metrics
    for project_name, metrics in metrics_by_project.items():
        row = existing_rows.get(
            project_name,
            {
                "Name of project": project_name,
                "Status": "unknown",
                "Risk Score": "",
                "Total Vuln": "",
                "Vuln (Critical)": "",
                "Vuln (High)": "",
                "Vuln (Medium)": "",
                "Vuln (Low)": "",
                "Vuln (Unassign)": "",
            },
        )

        if metrics is not None:
            def to_str(v):
                return "" if v is None else str(v)

            row["Risk Score"] = to_str(metrics["risk_score"])
            row["Total Vuln"] = to_str(metrics["total_vuln"])
            row["Vuln (Critical)"] = to_str(metrics["critical"])
            row["Vuln (High)"] = to_str(metrics["high"])
            row["Vuln (Medium)"] = to_str(metrics["medium"])
            row["Vuln (Low)"] = to_str(metrics["low"])
            row["Vuln (Unassign)"] = to_str(metrics["unassigned"])

        existing_rows[project_name] = row

    # Ghi lại CSV
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in existing_rows.values():
            writer.writerow(row)

    print("=" * 80)
    log_info(f"Đã cập nhật metrics vào: {csv_path}")


if __name__ == "__main__":
    main()
