from __future__ import annotations

import re
from pathlib import Path
from collections import Counter, defaultdict

from static_analyzer import PEStaticAnalyzer
from package_analyzer import PackageAnalyzer


class FolderStaticAnalyzer:
    SCRIPT_EXTS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".txt"}
    ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
    PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".drv"}

    SCRIPT_PATTERNS = {
        "urls": re.compile(r"https?://[^\s'\"<>]{8,}", re.I),
        "ips": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        "commands": re.compile(r"(?i)(?:powershell(?:\.exe)?|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget)[^\r\n]{0,120}"),
        "base64": re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
        "keywords": re.compile(r"(?i)\b(download|stringfromcharcode|invoke-expression|iex|startup|autorun|schtasks|run key|lsass)\b"),
    }

    def __init__(self):
        self.pe_analyzer = PEStaticAnalyzer()
        self.pkg_analyzer = PackageAnalyzer()

    def analyze(self, folder_path: str | Path) -> dict:
        root = Path(folder_path)
        if not root.exists() or not root.is_dir():
            return {"success": False, "error": f"Folder not found: {root}"}

        result = {
            "success": True,
            "folder_path": str(root),
            "folder_name": root.name,
            "summary": {
                "total_files": 0,
                "total_dirs": 0,
                "total_size": 0,
                "max_depth": 0,
                "pe_count": 0,
                "manifest_count": 0,
                "script_count": 0,
                "archive_count": 0,
                "text_count": 0,
                "unknown_count": 0,
            },
            "pe_files": [],
            "package_files": [],
            "script_files": [],
            "archives": [],
            "aggregate": {},
            "errors": [],
        }

        for path in root.rglob("*"):
            try:
                if path.is_dir():
                    result["summary"]["total_dirs"] += 1
                    depth = len(path.relative_to(root).parts)
                    result["summary"]["max_depth"] = max(result["summary"]["max_depth"], depth)
                    continue

                result["summary"]["total_files"] += 1
                result["summary"]["total_size"] += path.stat().st_size
                rel = str(path.relative_to(root))
                ext = path.suffix.lower()

                if ext in self.PE_EXTS:
                    pe_result = self.pe_analyzer.analyze(path)
                    result["pe_files"].append({"relative_path": rel, "analysis": pe_result})
                    result["summary"]["pe_count"] += 1
                    continue

                if PackageAnalyzer.is_package_file(path.name):
                    pkg_result = self.pkg_analyzer.analyze(path)
                    result["package_files"].append({"relative_path": rel, "analysis": pkg_result})
                    result["summary"]["manifest_count"] += 1
                    continue

                if ext in self.ARCHIVE_EXTS:
                    result["archives"].append({
                        "relative_path": rel,
                        "suffix": ext,
                        "size": path.stat().st_size,
                    })
                    result["summary"]["archive_count"] += 1
                    continue

                if ext in self.SCRIPT_EXTS:
                    result["script_files"].append(self._scan_script(path, root))
                    result["summary"]["script_count"] += 1
                    continue

                if ext in {".md", ".ini", ".yaml", ".yml", ".json", ".xml", ".cfg"}:
                    result["summary"]["text_count"] += 1
                else:
                    result["summary"]["unknown_count"] += 1

            except Exception as exc:
                result["errors"].append(f"{path}: {exc}")

        result["aggregate"] = self._aggregate(result)
        return result

    def _scan_script(self, path: Path, root: Path) -> dict:
        text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
        findings = {}
        for key, pat in self.SCRIPT_PATTERNS.items():
            findings[key] = list(dict.fromkeys(pat.findall(text)))[:50]

        return {
            "relative_path": str(path.relative_to(root)),
            "type": path.suffix.lower().lstrip(".") or "other",
            "size": path.stat().st_size,
            "findings": findings,
        }

    def _aggregate(self, result: dict) -> dict:
        risk_levels = Counter()
        categories = Counter()
        ecosystems = Counter()

        pe_scores = []
        suspicious_api_total = 0
        critical_api_total = 0
        high_api_total = 0
        medium_api_total = 0
        high_entropy_section_total = 0
        suspicious_section_name_total = 0
        tls_count = 0
        component_count_total = 0

        urls_total = 0
        ips_total = 0
        suspicious_commands_total = 0
        base64_total = 0

        dependencies_total = 0
        package_with_cpe_hint_total = 0

        for item in result["pe_files"]:
            a = item["analysis"]
            risk = a.get("risk", {})
            imports = a.get("imports", {})
            strings = a.get("strings", {})
            sections = a.get("sections", [])

            pe_scores.append(risk.get("score", 0))
            risk_levels[risk.get("level", "CLEAN")] += 1

            suspicious = imports.get("suspicious", [])
            suspicious_api_total += len(suspicious)
            critical_api_total += sum(1 for s in suspicious if s.get("risk") == "CRITICAL")
            high_api_total += sum(1 for s in suspicious if s.get("risk") == "HIGH")
            medium_api_total += sum(1 for s in suspicious if s.get("risk") == "MEDIUM")

            for cat, entries in (imports.get("by_category") or {}).items():
                categories[cat] += len(entries)

            high_entropy_section_total += sum(1 for s in sections if s.get("high_entropy"))
            suspicious_section_name_total += sum(1 for s in sections if s.get("suspicious_name"))
            tls_count += int(bool((a.get("pe_info") or {}).get("has_tls")))
            component_count_total += len(a.get("components", []))

            urls_total += len(strings.get("URLs", []))
            ips_total += len(strings.get("IP Addresses", []))
            suspicious_commands_total += len(strings.get("Suspicious Commands", []))
            base64_total += len(strings.get("Potential Base64", []))

        for item in result["package_files"]:
            a = item["analysis"]
            if not a.get("success"):
                continue
            ecosystems[a.get("ecosystem", "unknown")] += 1
            pkgs = a.get("packages", [])
            dependencies_total += len(pkgs)
            package_with_cpe_hint_total += sum(1 for p in pkgs if p.get("cpe_hints"))

        for item in result["script_files"]:
            f = item["findings"]
            urls_total += len(f.get("urls", []))
            ips_total += len(f.get("ips", []))
            suspicious_commands_total += len(f.get("commands", []))
            base64_total += len(f.get("base64", []))

        return {
            "risk_score_max": max(pe_scores) if pe_scores else 0,
            "risk_score_mean": round(sum(pe_scores) / len(pe_scores), 3) if pe_scores else 0.0,
            "risk_level_counts": dict(risk_levels),
            "suspicious_api_total": suspicious_api_total,
            "critical_api_total": critical_api_total,
            "high_api_total": high_api_total,
            "medium_api_total": medium_api_total,
            "high_entropy_section_total": high_entropy_section_total,
            "suspicious_section_name_total": suspicious_section_name_total,
            "tls_count": tls_count,
            "component_count_total": component_count_total,
            "urls_total": urls_total,
            "ips_total": ips_total,
            "suspicious_commands_total": suspicious_commands_total,
            "base64_total": base64_total,
            "detected_categories": dict(categories),
            "dependencies_total": dependencies_total,
            "ecosystems": dict(ecosystems),
            "package_with_cpe_hint_total": package_with_cpe_hint_total,
        }