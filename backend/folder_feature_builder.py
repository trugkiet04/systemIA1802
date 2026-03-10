from __future__ import annotations

from typing import Dict, Any


ALL_CATEGORIES = [
    "Process Injection",
    "Anti-Debugging",
    "Network Communication",
    "Code Execution",
    "Keylogging",
    "Registry Manipulation",
    "Cryptography",
    "Privilege Escalation",
    "Service Manipulation",
    "Dynamic Loading",
]

ALL_ECOSYSTEMS = [
    "python", "npm", "maven", "gradle", "composer", "ruby", "go", "cargo"
]


def build_folder_features(folder_result: Dict[str, Any]) -> Dict[str, Any]:
    s = folder_result.get("summary", {})
    a = folder_result.get("aggregate", {})

    total_files = max(s.get("total_files", 0), 1)

    feat = {
        "total_files": s.get("total_files", 0),
        "total_dirs": s.get("total_dirs", 0),
        "total_size_mb": round(s.get("total_size", 0) / (1024 * 1024), 4),
        "max_depth": s.get("max_depth", 0),

        "pe_count": s.get("pe_count", 0),
        "manifest_count": s.get("manifest_count", 0),
        "script_count": s.get("script_count", 0),
        "archive_count": s.get("archive_count", 0),
        "text_count": s.get("text_count", 0),
        "unknown_count": s.get("unknown_count", 0),

        "pe_ratio": s.get("pe_count", 0) / total_files,
        "script_ratio": s.get("script_count", 0) / total_files,
        "archive_ratio": s.get("archive_count", 0) / total_files,

        "pe_risk_score_max": a.get("risk_score_max", 0),
        "pe_risk_score_mean": a.get("risk_score_mean", 0.0),

        "suspicious_api_total": a.get("suspicious_api_total", 0),
        "critical_api_total": a.get("critical_api_total", 0),
        "high_api_total": a.get("high_api_total", 0),
        "medium_api_total": a.get("medium_api_total", 0),

        "high_entropy_section_total": a.get("high_entropy_section_total", 0),
        "suspicious_section_name_total": a.get("suspicious_section_name_total", 0),
        "tls_count": a.get("tls_count", 0),
        "component_count_total": a.get("component_count_total", 0),

        "urls_total": a.get("urls_total", 0),
        "ips_total": a.get("ips_total", 0),
        "suspicious_commands_total": a.get("suspicious_commands_total", 0),
        "base64_total": a.get("base64_total", 0),

        "dependencies_total": a.get("dependencies_total", 0),
        "package_with_cpe_hint_total": a.get("package_with_cpe_hint_total", 0),
    }

    risk_counts = a.get("risk_level_counts", {})
    for k in ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        feat[f"risk_count_{k.lower()}"] = risk_counts.get(k, 0)

    cat_counts = a.get("detected_categories", {})
    for cat in ALL_CATEGORIES:
        key = cat.lower().replace(" ", "_").replace("-", "_")
        feat[f"cat_{key}"] = cat_counts.get(cat, 0)

    eco_counts = a.get("ecosystems", {})
    for eco in ALL_ECOSYSTEMS:
        feat[f"ecosystem_{eco}"] = eco_counts.get(eco, 0)

    return feat