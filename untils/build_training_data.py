# untils/build_training_data.py

"""
Build CVE Severity Training Dataset.

Sources
-------
Mode 1 — keyword (default, fast ~10 min):
    NVD API v2 keyword searches covering major software categories.
    Produces ~5k–15k records depending on rate limits.

Mode 2 — bulk (recommended for thesis, ~30–60 min):
    Downloads ALL CVEs from NVD API v2 without keyword filter.
    Produces ~220k+ records for a much more representative dataset.
    Usage: python untils/build_training_data.py --bulk

Output
------
    data/training/cve_severity_train.csv
    Columns: cve_id, description, cvss_score, severity, vector_string

Dataset Statistics
------------------
    After running this script the class distribution is printed.
    Typical NVD distribution: LOW ~5%, MEDIUM ~45%, HIGH ~40%, CRITICAL ~10%

Academic Reference
------------------
    NVD (National Vulnerability Database) — https://nvd.nist.gov
    NIST. (2024). National Vulnerability Database. National Institute of
    Standards and Technology. https://services.nvd.nist.gov/rest/json/cves/2.0/
"""

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

import requests

ROOT = Path(__file__).parent.parent

# ── Configuration ─────────────────────────────────────────────────────────────

# Keywords for Mode 1 (keyword search) — aligned with thesis scope
SEARCH_KEYWORDS = [
    # Web servers & proxies
    "apache http server", "nginx", "tomcat", "iis", "lighttpd", "caddy",
    "haproxy", "squid proxy", "varnish", "traefik",
    # Databases
    "mysql", "postgresql", "mongodb", "redis", "sqlite", "oracle database",
    "microsoft sql server", "elasticsearch", "cassandra", "mariadb",
    "couchdb", "neo4j", "memcached", "influxdb", "clickhouse",
    # Languages & runtimes
    "python", "php", "java", "node.js", "ruby", "golang", "rust",
    "perl", "r language", "swift", "kotlin", "scala",
    # Security libraries
    "openssl", "openssh", "gnutls", "nss", "mbedtls", "bouncycastle",
    "libressl", "wolfssl", "cryptography library",
    # OS & kernel
    "linux kernel", "windows", "android", "ios", "macos",
    "freebsd", "openbsd", "netbsd", "solaris", "ubuntu", "debian", "centos",
    # CMS & platforms
    "wordpress", "drupal", "joomla", "magento", "typo3",
    "shopify", "prestashop", "opencart", "ghost cms", "concrete5",
    # Browsers
    "chrome", "firefox", "safari", "edge", "opera", "brave",
    "chromium", "webkit", "v8 engine",
    # Network / infrastructure
    "cisco ios", "juniper", "palo alto", "fortinet", "f5 big-ip",
    "sonicwall", "checkpoint", "netgear", "d-link", "zyxel",
    "openvpn", "wireguard", "strongswan", "cisco asa",
    # Virtualisation & containers
    "vmware", "docker", "kubernetes", "virtualbox", "xen",
    "hyper-v", "kvm", "qemu", "lxc", "containerd", "podman",
    # Frameworks & libraries
    "log4j", "spring framework", "struts", "django", "rails", "laravel",
    "curl", "libssl", "libpng", "zlib", "expat",
    "flask", "fastapi", "express.js", "react", "angular", "vue.js",
    "hibernate", "jackson", "gson", "yaml library",
    # Productivity & end-user apps
    "adobe acrobat", "microsoft office", "outlook", "exchange",
    "winrar", "7-zip", "zoom", "slack", "putty", "filezilla",
    "libreoffice", "gimp", "vlc media player", "adobe reader",
    "microsoft teams", "discord", "telegram", "signal",
    # Developer tools
    "git", "jenkins", "gitlab", "sonarqube", "ansible", "terraform",
    "github actions", "artifactory", "hashicorp vault", "grafana",
    "prometheus", "kibana", "logstash", "apache kafka", "rabbitmq",
    # Email & messaging
    "postfix", "sendmail", "dovecot", "exim", "zimbra",
    "microsoft exchange", "roundcube", "horde",
    # IoT & embedded
    "openwrt", "dd-wrt", "busybox", "uboot", "raspberry pi",
    "arduino", "mqtt", "modbus",
    # Vulnerability types (description-level) — high signal for severity
    "buffer overflow", "sql injection", "cross-site scripting",
    "remote code execution", "privilege escalation", "path traversal",
    "deserialization", "use after free", "integer overflow",
    "null pointer dereference", "heap overflow", "stack overflow",
    "format string", "command injection", "xxe injection",
    "server-side request forgery", "open redirect", "csrf",
    "insecure deserialization", "xml injection", "ldap injection",
    "directory traversal", "race condition", "double free",
    "type confusion", "out of bounds read", "out of bounds write",
    "improper authentication", "improper authorization",
    "missing authentication", "hard-coded credentials",
    "information disclosure", "denial of service", "memory corruption",
]

NVD_API     = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
OUTPUT_FILE = ROOT / "data/training/cve_severity_train.csv"
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# Results-per-page limit imposed by NVD API
NVD_PAGE_LIMIT = 2000


# ── CVE parser ────────────────────────────────────────────────────────────────

def _parse_vuln(vuln: dict) -> dict | None:
    """
    Extract CVE fields including CWE labels.

    Columns produced
    ----------------
    cve_id, description, cvss_score, severity, vector_string, cwe_ids

    cwe_ids : pipe-separated CWE identifiers, e.g. "CWE-94|CWE-78"
              Empty string when NVD has no weakness data for the CVE.
    """
    cve    = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    # English description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "").strip()
            break
    if not desc or len(desc) < 20:
        return None

    # CVSS metrics — prefer v3.1 → v3.0 → v2
    metrics  = cve.get("metrics", {})
    score, severity, vector = 0.0, "NONE", ""

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m  = metrics[key][0]
            cd = m.get("cvssData", {})
            score  = float(cd.get("baseScore", 0))
            vector = cd.get("vectorString", "")

            if key in ("cvssMetricV31", "cvssMetricV30"):
                severity = cd.get("baseSeverity", "NONE").upper()
            else:
                # CVSS v2: map score to severity manually
                severity = (
                    "HIGH"   if score >= 7.0 else
                    "MEDIUM" if score >= 4.0 else
                    "LOW"    if score > 0    else "NONE"
                )
            break

    if severity not in VALID_SEVERITIES:
        return None

    # CWE extraction (Hướng 3 dataset) ────────────────────────────────────────
    # NVD API returns: cve.weaknesses[].description[{lang, value}]
    # value is a CWE-ID string like "CWE-94", "CWE-78", or "NVD-CWE-Other"
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("lang") == "en":
                val = d.get("value", "").strip()
                # Only keep proper CWE-nnn IDs, skip NVD-CWE-noinfo / Other
                if val.startswith("CWE-") and val[4:].isdigit():
                    if val not in cwe_ids:
                        cwe_ids.append(val)

    return {
        "cve_id":        cve_id,
        "description":   desc,
        "cvss_score":    score,
        "severity":      severity,
        "vector_string": vector,
        "cwe_ids":       "|".join(cwe_ids),   # e.g. "CWE-94|CWE-78" or ""
    }


# ── NVD API helpers ───────────────────────────────────────────────────────────

def _make_headers(api_key: str) -> dict:
    return {"apiKey": api_key} if api_key else {}


def _sleep(api_key: str) -> None:
    """Respect NVD rate limits: 50 req/30s with key, 5 req/30s without."""
    time.sleep(0.7 if api_key else 6.5)


def _fetch_page(params: dict, headers: dict) -> tuple[list, int]:
    """
    Fetch one page from NVD API.
    Returns (vulnerabilities_list, total_results).
    """
    for attempt in range(3):
        try:
            r = requests.get(NVD_API, params=params, headers=headers, timeout=60)
            r.raise_for_status()
            data = r.json()
            return data.get("vulnerabilities", []), data.get("totalResults", 0)
        except Exception as exc:
            wait = 2 ** attempt * 5
            print(f"    [retry {attempt+1}] {exc} — waiting {wait}s")
            time.sleep(wait)
    return [], 0


# ── Mode 1: keyword search ────────────────────────────────────────────────────

def fetch_by_keyword(keyword: str, api_key: str, max_per_kw: int = 300) -> list:
    """Query NVD API with keywordSearch, return parsed records."""
    headers = _make_headers(api_key)
    records: list[dict] = []
    start = 0

    while len(records) < max_per_kw:
        _sleep(api_key)
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": min(NVD_PAGE_LIMIT, max_per_kw - len(records)),
            "startIndex":     start,
        }
        vulns, total = _fetch_page(params, headers)
        if not vulns:
            break
        for v in vulns:
            p = _parse_vuln(v)
            if p:
                records.append(p)
        start += len(vulns)
        if start >= total:
            break

    return records


def run_keyword_mode(api_key: str, max_per_kw: int = 300) -> dict[str, dict]:
    """Collect CVEs via keyword search + NVD cache. Returns {cve_id: record}."""
    all_records: dict[str, dict] = {}

    # Load existing NVD cache first
    cache_dir = ROOT / "data/cache/nvd"
    if cache_dir.exists():
        print(f"  Loading local cache from {cache_dir.name} …")
        for f in sorted(cache_dir.glob("*.json")):
            try:
                with open(f, encoding="utf-8") as fh:
                    d = json.load(fh)
                desc  = (d.get("description") or "").strip()
                sev   = (d.get("severity")    or "").upper()
                score = float(d.get("cvss_score") or 0)
                vec   = d.get("vector_string", "")
                cid   = d.get("cve_id", f.stem)
                if desc and sev in VALID_SEVERITIES:
                    all_records[cid] = {
                        "cve_id": cid, "description": desc,
                        "cvss_score": score, "severity": sev, "vector_string": vec,
                    }
            except Exception:
                pass
        print(f"  Cache: {len(all_records):,} records")

    # Keyword searches
    print(f"\n  Querying NVD API ({len(SEARCH_KEYWORDS)} keywords, max {max_per_kw} each) …")
    for kw in SEARCH_KEYWORDS:
        before  = len(all_records)
        fetched = fetch_by_keyword(kw, api_key, max_per_kw)
        for r in fetched:
            all_records.setdefault(r["cve_id"], r)
        added = len(all_records) - before
        print(f"    {kw:<40}  +{added:4d}  total={len(all_records):,}")

    return all_records


# ── Mode 2: bulk (all CVEs, paginated) ───────────────────────────────────────

def run_bulk_mode(api_key: str, max_total: int = 0) -> dict[str, dict]:
    """
    Download ALL CVEs from NVD API v2 by paginating without keyword filter.

    Parameters
    ----------
    api_key   : NVD API key (strongly recommended, otherwise rate-limited)
    max_total : cap on records (0 = no cap, download everything)

    Returns
    -------
    dict {cve_id: record}
    """
    headers    = _make_headers(api_key)
    all_records: dict[str, dict] = {}
    start      = 0

    print("  Fetching first page to discover total …")
    _sleep(api_key)
    _, total = _fetch_page({"resultsPerPage": 1, "startIndex": 0}, headers)
    cap = total if max_total == 0 else min(total, max_total)
    print(f"  NVD total CVEs: {total:,} — downloading up to {cap:,}")

    while start < cap:
        _sleep(api_key)
        params = {
            "resultsPerPage": NVD_PAGE_LIMIT,
            "startIndex":     start,
        }
        vulns, _ = _fetch_page(params, headers)
        if not vulns:
            print(f"  [WARN] Empty page at startIndex={start}")
            break

        for v in vulns:
            p = _parse_vuln(v)
            if p:
                all_records.setdefault(p["cve_id"], p)

        start += len(vulns)
        pct    = start / cap * 100
        print(f"  Downloaded {start:>6,} / {cap:,}  ({pct:5.1f}%)  "
              f"valid={len(all_records):,}", end="\r", flush=True)

        if start >= cap:
            break

    print()
    return all_records


# ── Balance dataset ───────────────────────────────────────────────────────────

def balance_dataset(records: list, strategy: str = "oversample") -> list:
    """
    Address class imbalance.

    Strategies
    ----------
    oversample : duplicate minority class samples until they reach
                 the count of the second-most-common class.
                 (avoids drastically inflating dataset)
    none       : return records as-is
    """
    if strategy == "none":
        return records

    import random
    random.seed(42)

    by_class: dict[str, list] = {}
    for r in records:
        by_class.setdefault(r["severity"], []).append(r)

    counts = {k: len(v) for k, v in by_class.items()}
    sorted_counts = sorted(counts.values(), reverse=True)

    if len(sorted_counts) < 2:
        return records

    # Target = 2nd highest count (don't blindly match the largest to avoid noise)
    target = sorted_counts[1]

    balanced = []
    for sev, samples in by_class.items():
        balanced.extend(samples)
        if len(samples) < target:
            needed  = target - len(samples)
            extras  = random.choices(samples, k=needed)
            balanced.extend(extras)
            print(f"    Oversampled {sev}: {len(samples)} → {len(samples) + needed}")

    random.shuffle(balanced)
    return balanced


# ── Save CSV ──────────────────────────────────────────────────────────────────

def save_csv(records: list, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # cwe_ids added for Hướng 3 — CWE behavior prediction training data
    fields = ["cve_id", "description", "cvss_score", "severity", "vector_string", "cwe_ids"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)
    print(f"\n  Saved {len(records):,} records → {path}")

    # Also save a CWE-labeled subset for Hướng 3
    cwe_path  = path.parent / "cve_cwe_train.csv"
    cwe_fields = ["cve_id", "description", "cwe_ids", "severity"]
    cwe_records = [r for r in records if r.get("cwe_ids")]
    if cwe_records:
        with open(cwe_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cwe_fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(cwe_records)
        pct = len(cwe_records) / len(records) * 100
        print(f"  Saved {len(cwe_records):,} CWE-labeled records ({pct:.1f}%) → {cwe_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def print_distribution(records: list) -> None:
    counts = Counter(r["severity"] for r in records)
    total  = len(records)
    print(f"\n  Dataset: {total:,} records")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n   = counts.get(s, 0)
        pct = n / total * 100 if total else 0
        bar = "█" * int(pct / 2)
        print(f"    {s:<10} {n:>7,}  ({pct:5.1f}%)  {bar}")


def main():
    parser = argparse.ArgumentParser(
        description="Build CVE severity training dataset from NVD API v2"
    )
    parser.add_argument(
        "--bulk",
        action="store_true",
        help=(
            "Download ALL CVEs from NVD API (no keyword filter). "
            "Produces ~220k+ records. Requires API key for reasonable speed."
        ),
    )
    parser.add_argument(
        "--max", type=int, default=0,
        help="Cap on records for --bulk mode (0 = no cap, download everything).",
    )
    parser.add_argument(
        "--max-per-kw", type=int, default=300,
        help="Max records per keyword in keyword mode (default 300).",
    )
    parser.add_argument(
        "--balance",
        choices=["oversample", "none"],
        default="oversample",
        help="Class balancing strategy (default: oversample minority classes).",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("NVD_API_KEY", ""),
        help=(
            "NVD API key. Without key: 5 req/30s. "
            "Get a free key at https://nvd.nist.gov/developers/request-an-api-key"
        ),
    )
    args = parser.parse_args()

    print("=" * 60)
    if args.bulk:
        print("BUILD CVE DATASET — BULK MODE (all NVD CVEs)")
    else:
        print("BUILD CVE DATASET — KEYWORD MODE")
    print("=" * 60)

    if not args.api_key:
        print(
            "\n[WARN] No NVD API key found. Downloads will be rate-limited (slow).\n"
            "       Get a free key: https://nvd.nist.gov/developers/request-an-api-key\n"
            "       Then set: export NVD_API_KEY=your_key_here\n"
        )
    else:
        print(f"\n[OK] NVD API key: {args.api_key[:8]}…")

    # ── Collect records ──
    if args.bulk:
        print("\n[1/3] Downloading ALL CVEs from NVD API v2 …")
        all_records = run_bulk_mode(args.api_key, max_total=args.max)
    else:
        print("\n[1/3] Collecting CVEs via keyword search …")
        all_records = run_keyword_mode(args.api_key, max_per_kw=args.max_per_kw)

    records = list(all_records.values())

    # ── Before balancing ──
    print("\n[2/3] Class distribution BEFORE balancing:")
    print_distribution(records)

    # ── Balance ──
    if args.balance == "oversample" and records:
        print(f"\n  Applying '{args.balance}' balancing …")
        records = balance_dataset(records, strategy=args.balance)
        print("\n  Class distribution AFTER balancing:")
        print_distribution(records)

    # ── Save ──
    print("\n[3/3] Saving …")
    save_csv(records, OUTPUT_FILE)

    print("\n" + "=" * 60)
    print("DONE")
    print("=" * 60)
    print("\nNext steps:")
    print("  python untils/train_severity_model.py       # TF-IDF + LR (fast)")
    print("  python untils/finetune_bert_severity.py     # SecBERT fine-tune (GPU)")
    print("  python untils/run_training_pipeline.py      # run everything at once")


if __name__ == "__main__":
    main()
