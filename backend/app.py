"""
Software Vulnerability Assessment Tool
Flask Web Server

Thesis: Nghiên cứu và Phát triển Công cụ Đánh giá Lỗ hổng Phần mềm
        kết hợp AI và Cơ sở Dữ liệu CVE

API Endpoints:
  POST /api/analyze          - Analyze a file (PE binary OR package manifest)
  POST /api/analyze-packages - Analyze package manifest (alias, same as /api/analyze)
  POST /api/search           - Search by software name + version
  POST /api/query-cpe        - Query CVEs by CPE string
  POST /api/export-all       - Export ALL CVEs for a CPE (no limit)
  GET  /api/status           - System status & enabled features
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename
from pathlib import Path
import sys
import os

# ── Path setup ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / 'ai'))

# ── Core modules ─────────────────────────────────────────────────────────────
from cpe_extractor       import CPEExtractor
from nvd_api_v2          import NVDAPIv2
from static_analyzer     import PEStaticAnalyzer
from package_analyzer    import PackageAnalyzer, PackageAnalyzer as _PKG
from ai_analyzer         import (
    ai_match_cpe, ai_analyze_severity, ai_analyze_static_behavior,
    is_available as ai_available,
)
from cpe_semantic_matcher import (
    match_best as sem_match_best, is_available as sem_available,
)
from cwe_predictor import CWEPredictor

# ── Unified AI pipeline (replaces individual model imports) ──────────────────
from ai.severity_pipeline import (
    enrich_cves   as ai_enrich_severity,
    is_available  as severity_pipeline_available,
    get_status    as severity_status,
)
from ai.relevance_scorer import (
    score_cves              as ai_score_relevance,
    get_profile_text        as ai_profile_text,
    is_semantic_available   as secbert_available,
)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder='../frontend/templates',
    static_folder='../frontend/static',
)
CORS(app)

app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB

UPLOAD_DIR = BASE_DIR.parent / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)

# ── Globals ───────────────────────────────────────────────────────────────────
nvd_api       = None
cpe_extractor = None
pe_analyzer   = None
pkg_analyzer  = None
cwe_predictor = None


# ── Initialization ────────────────────────────────────────────────────────────

def init_app():
    global nvd_api, cpe_extractor, pe_analyzer, pkg_analyzer, cwe_predictor

    print("=" * 70)
    print("[*] SOFTWARE VULNERABILITY ASSESSMENT TOOL")
    print("    AI + CVE Database Edition")
    print("=" * 70)

    # NVD API key (set here or via NVD_API_KEY env var)
    API_KEY = "4a29ba81-21a1-4e9d-84ff-e806f576c061"
    api_key = API_KEY or os.getenv('NVD_API_KEY')

    if not api_key:
        print("[!] WARNING: No NVD API key — queries will be slow (5 req/30s)")

    nvd_api       = NVDAPIv2(api_key)
    cpe_extractor = CPEExtractor()
    pe_analyzer   = PEStaticAnalyzer()
    pkg_analyzer  = PackageAnalyzer()
    cwe_predictor = CWEPredictor(nvd_api)

    print("[+] NVD API v2 initialized")
    print("[+] CPE Extractor initialized")
    print("[+] PE Static Analyzer initialized")
    print("[+] Package Analyzer initialized")
    print("[+] CWE Predictor initialized (Hướng 3)")
    print(f"    Supported: {', '.join(PackageAnalyzer.supported_filenames()[:8])} ...")

    print()
    print("[*] AI Feature Status:")

    if ai_available():
        print("[+] Claude AI (CPE matching + risk narrative): ENABLED")
    else:
        print("[i] Claude AI: DISABLED (set ANTHROPIC_API_KEY)")

    if sem_available():
        print("[+] Semantic CPE Matcher (FAISS): ENABLED")
    else:
        print("[i] Semantic CPE Matcher: DISABLED (run: python untils/build_cpe_index.py)")

    sv = severity_status()
    if sv['available']:
        active = [k for k, v in sv.items() if v and k != 'available']
        print(f"[+] Severity Pipeline: ENABLED ({', '.join(active)})")
    else:
        print("[i] Severity Pipeline: DISABLED (no models trained)")

    if secbert_available():
        print("[+] SecBERT Semantic Relevance: ENABLED")
    else:
        print("[i] SecBERT Semantic Relevance: DISABLED (pip install transformers torch)")

    print()


init_app()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── /api/analyze ─────────────────────────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
@app.route('/api/analyze-packages', methods=['POST'])
def analyze_file():
    """
    Universal file analysis endpoint.
    Accepts:
      - PE binary (.exe / .dll / .sys) → static analysis + CVE lookup
      - Package manifest (requirements.txt, package.json, pom.xml, etc.)
                         → dependency extraction + CVE per package
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    filepath = Path(app.config['UPLOAD_FOLDER']) / filename

    try:
        file.save(str(filepath))

        ext = filepath.suffix.lower()

        # ── Route to appropriate handler ──────────────────────────────────
        if ext in ('.exe', '.dll', '.sys', '.ocx', '.drv'):
            return _analyze_pe(filepath, filename)
        elif PackageAnalyzer.is_package_file(filename):
            return _analyze_package_manifest(filepath, filename)
        else:
            # Attempt PE first, then package manifest
            try:
                import pefile
                pefile.PE(str(filepath), fast_load=True).close()
                return _analyze_pe(filepath, filename)
            except Exception:
                # Try as package manifest
                if pkg_analyzer.detect_ecosystem(filepath):
                    return _analyze_package_manifest(filepath, filename)
                return jsonify({
                    'success': False,
                    'error':   (
                        f'Unsupported file type: {ext or filename}. '
                        'Upload a PE binary (.exe/.dll/.sys) or a package manifest '
                        '(requirements.txt, package.json, pom.xml, etc.)'
                    ),
                }), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        try:
            filepath.unlink(missing_ok=True)
        except Exception:
            pass


def _resolve_cpe(cpe_info: dict, filename: str) -> tuple[str, str, str, str, dict, dict]:
    """
    Attempt to resolve a CPE using AI and FAISS fallback.
    Returns (cpe, vendor, product, version, ai_cpe_result, sem_cpe_result).
    """
    cpe     = cpe_info.get('cpe')
    vendor  = cpe_info.get('vendor', '')
    product = cpe_info.get('product', '')
    version = cpe_info.get('version', '')
    extraction_method = cpe_info.get('extraction_method', '')

    ai_cpe_result  = None
    sem_cpe_result = None

    # Use AI when: explicit fallback modes OR pe_version_info gave unknown/generic vendor
    _generic_vendors = {'unknown', 'microsoft_corporation', ''}
    needs_ai = (
        extraction_method in ('generic_fallback', 'filename_pattern', 'manual_input')
        or (extraction_method == 'pe_version_info' and vendor in _generic_vendors)
        or not cpe  # no CPE resolved at all
    )

    if needs_ai:
        file_meta  = cpe_info.get('file_info', {})
        # Prefer ProductName from VersionInfo for richer context
        query_name = (
            file_meta.get('ProductName') or product or filename or ''
        ).strip()

        # 1. Claude AI (highest accuracy — understands product names semantically)
        if ai_available():
            ai_cpe_result = ai_match_cpe(
                product_name=file_meta.get('ProductName') or product or filename or '',
                company_name=file_meta.get('CompanyName', ''),
                filename=file_meta.get('FileName', filename),
                version=version or '',
            )
            if ai_cpe_result.get('success') and \
               ai_cpe_result.get('confidence') in ('high', 'medium'):
                vendor  = ai_cpe_result['vendor']
                product = ai_cpe_result['product']
                cpe     = cpe_extractor._build_cpe(vendor, product, version or '')

        # 2. FAISS semantic fallback
        if sem_available() and query_name and \
           not (ai_cpe_result and ai_cpe_result.get('success')):
            sem_cpe_result = sem_match_best(query_name, min_score=0.50)
            if sem_cpe_result and \
               sem_cpe_result.get('confidence') in ('high', 'medium'):
                vendor  = sem_cpe_result['vendor']
                product = sem_cpe_result['product']
                cpe     = cpe_extractor._build_cpe(vendor, product, version or '')

    return cpe, vendor, product, version, ai_cpe_result, sem_cpe_result


def _enrich_cves(cves: list, software_analysis: dict | None = None) -> list:
    """Apply unified AI severity + relevance scoring to a CVE list."""
    if not cves:
        return cves

    # Unified severity ensemble
    cves = ai_enrich_severity(cves)

    # Relevance scoring (only when we have a software context)
    if software_analysis:
        cves = ai_score_relevance(software_analysis, cves)

    return cves


def _analyze_pe(filepath: Path, filename: str):
    """Full PE binary static analysis + CVE lookup."""

    print(f"\n[PE] Analyzing: {filename}")

    # ── 1. Static analysis ────────────────────────────────────────────────────
    result = pe_analyzer.analyze(filepath)
    result.update({
        'analysis_type': 'binary',
        'cpe':           None,
        'cpe_info':      {},
        'vulnerabilities': [],
        'cve_statistics': {},
    })

    # ── 2. CPE extraction ─────────────────────────────────────────────────────
    try:
        cpe_info = cpe_extractor.extract_from_file(filepath)
        cpe, vendor, product, version, ai_cpe, sem_cpe = \
            _resolve_cpe(cpe_info, filename)

        result['ai_cpe']  = ai_cpe
        result['sem_cpe'] = sem_cpe
        result['cpe']     = cpe
        result['cpe_info'] = {
            'vendor':   vendor,
            'product':  product,
            'version':  version,
            'extraction_method': cpe_info.get('extraction_method', ''),
        }

        # ── 3. CVE lookup ─────────────────────────────────────────────────────
        if cpe:
            print(f"[PE] Querying NVD: {cpe}")
            cves = nvd_api.search_by_cpe(cpe, max_results=50)
            stats = _calc_stats(cves)
            print(f"[PE] Found {len(cves)} CVEs")

            cves = _enrich_cves(cves, result)
            result['behavior_profile_text'] = ai_profile_text(result)

            result['vulnerabilities'] = cves[:50]
            result['cve_statistics']  = stats

            # Embedded component CVEs
            component_cves = _lookup_component_cves(result.get('components', []))
            if component_cves:
                existing_ids = {c.get('cve_id') for c in cves}
                new_cves = [c for c in component_cves if c.get('cve_id') not in existing_ids]
                result['component_vulnerabilities'] = new_cves[:50]
                result['component_cve_count']       = len(component_cves)

            # AI risk narrative
            if ai_available() and cves:
                result['ai_analysis'] = ai_analyze_severity(
                    software_info={
                        'name':    f"{vendor} {product}",
                        'vendor':  vendor,
                        'product': product,
                        'version': version or '',
                    },
                    cves=cves,
                    stats=stats,
                )
        else:
            print(f"[PE] No CPE resolved — skipping CVE lookup")

        # ── Hướng 3: CWE Behavior Prediction (fallback) ───────────────────────
        # Kích hoạt khi:
        #   (a) Không xác định được CPE → không có CVE nào từ NVD
        #   (b) CPE có nhưng NVD trả về 0 CVE
        no_cves = len(result.get('vulnerabilities', [])) == 0
        if no_cves:
            print("[PE] No CVEs from CPE lookup → running CWE behavior prediction")
            cwe_result = cwe_predictor.predict_and_fetch(result)
            result['cwe_analysis'] = cwe_result

            # Nếu CWE prediction tìm được CVE, dùng làm vulnerabilities
            if cwe_result.get('cve_results'):
                cwe_cves = cwe_result['cve_results']
                cwe_cves = _enrich_cves(cwe_cves, result)
                result['vulnerabilities'] = cwe_cves[:50]
                result['cve_statistics']  = _calc_stats(cwe_cves)
                result['cve_source']      = 'cwe_behavior_prediction'

        # AI static behavior (when no CVEs or high-risk file)
        risk_level = result.get('risk', {}).get('level', 'CLEAN')
        no_cves    = len(result.get('vulnerabilities', [])) == 0
        if ai_available() and (no_cves or risk_level in ('HIGH', 'CRITICAL')):
            result['ai_static_behavior'] = ai_analyze_static_behavior(result)

    except Exception as e:
        print(f"[PE] CPE/CVE step error: {e}")
        result['cpe_error'] = str(e)

    print(f"[PE] Done — Risk: {result.get('risk', {}).get('level', '?')} | "
          f"CVEs: {len(result.get('vulnerabilities', []))}")

    return jsonify(result)


def _lookup_component_cves(components: list) -> list:
    """Query NVD CVEs for all embedded components."""
    found = []
    for comp in components:
        vendor  = comp.get('cpe_vendor', '')
        product = comp.get('cpe_product', '')
        version = comp.get('version', '')
        if vendor and product:
            comp_cpe = cpe_extractor._build_cpe(vendor, product, version)
            if comp_cpe:
                cves = nvd_api.search_by_cpe(comp_cpe, max_results=20)
                for cv in cves:
                    cv['source_component']         = comp['name']
                    cv['source_component_version'] = version
                found.extend(cves)
    return found


def _analyze_package_manifest(filepath: Path, filename: str):
    """Parse package manifest → per-package CVE lookup."""

    print(f"\n[PKG] Analyzing: {filename}")

    parse_result = pkg_analyzer.analyze(filepath)
    if not parse_result.get('success'):
        return jsonify({
            'success': False,
            'error':   parse_result.get('error', 'Parse failed'),
        }), 400

    ecosystem = parse_result['ecosystem']
    packages  = parse_result['packages']
    print(f"[PKG] Ecosystem: {ecosystem} | Packages: {len(packages)}")

    results_per_pkg = []
    all_cves        = []
    total_unique_ids: set[str] = set()

    for pkg in packages:
        name    = pkg.get('name', '')
        version = pkg.get('version', '')
        hints   = pkg.get('cpe_hints')

        if not name:
            continue

        # ── Resolve CPE ────────────────────────────────────────────────────
        cpe = None
        cpe_vendor  = ''
        cpe_product = ''

        # Use known CPE hints first
        if hints:
            cpe_vendor  = hints['vendor']
            cpe_product = hints['product']
            cpe         = cpe_extractor._build_cpe(cpe_vendor, cpe_product, version)

        # Fallback: AI CPE matching
        if not cpe and ai_available():
            ai_r = ai_match_cpe(
                product_name=name,
                company_name='',
                filename='',
                version=version or '',
            )
            if ai_r.get('success') and ai_r.get('confidence') in ('high', 'medium'):
                cpe_vendor  = ai_r['vendor']
                cpe_product = ai_r['product']
                cpe         = cpe_extractor._build_cpe(cpe_vendor, cpe_product, version)

        # Fallback: FAISS semantic
        if not cpe and sem_available():
            query = f"{name} {version}".strip()
            sem_r = sem_match_best(query, min_score=0.50)
            if sem_r and sem_r.get('confidence') in ('high', 'medium'):
                cpe_vendor  = sem_r['vendor']
                cpe_product = sem_r['product']
                cpe         = cpe_extractor._build_cpe(cpe_vendor, cpe_product, version)

        # ── Query NVD ──────────────────────────────────────────────────────
        cves = []
        if cpe:
            cves = nvd_api.search_by_cpe(cpe, max_results=20)
            # Keyword fallback when CPE yields 0
            if not cves:
                kw = f"{name} {version}".strip()
                cves = nvd_api.search_by_keyword(kw, max_results=10)

        cves = ai_enrich_severity(cves)
        stats = _calc_stats(cves)

        pkg_result = {
            'name':         name,
            'version':      version,
            'ecosystem':    ecosystem,
            'cpe':          cpe,
            'cpe_vendor':   cpe_vendor,
            'cpe_product':  cpe_product,
            'cves':         cves[:20],
            'cve_count':    len(cves),
            'statistics':   stats,
        }
        results_per_pkg.append(pkg_result)

        # Accumulate for global stats
        for cv in cves:
            cid = cv.get('cve_id', '')
            if cid and cid not in total_unique_ids:
                total_unique_ids.add(cid)
                cv['source_package'] = name
                all_cves.append(cv)

    total_stats = _calc_stats(all_cves)

    # AI global narrative
    ai_analysis = None
    if ai_available() and all_cves:
        ai_analysis = ai_analyze_severity(
            software_info={
                'name':    filename,
                'vendor':  '',
                'product': filename,
                'version': ecosystem,
            },
            cves=all_cves[:50],
            stats=total_stats,
        )

    print(f"[PKG] Done — {len(packages)} packages | {len(all_cves)} unique CVEs")

    return jsonify({
        'success':         True,
        'analysis_type':   'packages',
        'filename':        filename,
        'ecosystem':       ecosystem,
        'packages':        results_per_pkg,
        'total_packages':  len(packages),
        'total_unique_cves': len(all_cves),
        'all_cves':        all_cves[:100],
        'statistics':      total_stats,
        'ai_analysis':     ai_analysis,
    })


# ── /api/search ───────────────────────────────────────────────────────────────

@app.route('/api/search', methods=['POST'])
def search_by_name():
    """Search vulnerabilities by software name + version."""
    data = request.get_json()
    if not data or 'software_name' not in data:
        return jsonify({'success': False, 'error': 'software_name is required'}), 400

    software_name = data['software_name']
    version       = data.get('version', '')

    try:
        cpe_info = cpe_extractor.extract_from_software_name(software_name, version)
        cpe, vendor, product, version, ai_cpe, sem_cpe = \
            _resolve_cpe(cpe_info, software_name)

        max_results = data.get('max_results', None)

        # Query NVD by CPE if resolved, else go straight to keyword search
        cves        = []
        data_source = 'NVD (keyword search)'
        if cpe:
            cves        = nvd_api.search_by_cpe(cpe, max_results=max_results)
            data_source = 'NVD (CPE query)'

        # Keyword fallback: CPE resolved but 0 results, OR CPE not resolved at all
        if not cves:
            kw          = f"{software_name} {version}".strip() if version else software_name
            cves        = nvd_api.search_by_keyword(kw, max_results=max_results or 50)
            data_source = 'NVD (keyword search)'

        if not cves and not cpe:
            return jsonify({'success': False, 'error': 'Could not resolve CPE or find CVEs for this software'})

        stats = _calc_stats(cves)
        cves  = ai_enrich_severity(cves)

        ai_analysis = None
        if ai_available() and cves:
            ai_analysis = ai_analyze_severity(
                software_info={
                    'name':    software_name,
                    'vendor':  vendor,
                    'product': product,
                    'version': version or '',
                },
                cves=cves,
                stats=stats,
            )

        return jsonify({
            'success':      True,
            'analysis_type': 'search',
            'software_info': {
                'name':    software_name,
                'version': version,
                'vendor':  vendor,
                'product': product,
            },
            'cpe':           cpe,
            'total_cves':    stats['total_cves'],
            'vulnerabilities': cves[:50],
            'statistics':    stats,
            'data_source':   data_source,
            'ai_cpe':        ai_cpe,
            'sem_cpe':       sem_cpe,
            'ai_analysis':   ai_analysis,
            'note':          f"Showing first 50 of {stats['total_cves']} CVEs"
                             if stats['total_cves'] > 50 else None,
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── /api/query-cpe ────────────────────────────────────────────────────────────

@app.route('/api/query-cpe', methods=['POST'])
def query_cpe():
    """Query CVEs by a CPE 2.3 string."""
    data = request.get_json()
    if not data or 'cpe' not in data:
        return jsonify({'success': False, 'error': 'cpe is required'}), 400

    cpe         = data['cpe']
    max_results = data.get('max_results', None)

    try:
        cves  = nvd_api.search_by_cpe(cpe, max_results=max_results)
        stats = _calc_stats(cves)
        cves  = ai_enrich_severity(cves)

        parts    = cpe.split(':')
        sw_name  = f"{parts[3]} {parts[4]}" if len(parts) > 4 else cpe
        sw_ver   = parts[5] if len(parts) > 5 else ''

        ai_analysis = None
        if ai_available() and cves:
            ai_analysis = ai_analyze_severity(
                software_info={'name': sw_name, 'version': sw_ver},
                cves=cves,
                stats=stats,
            )

        return jsonify({
            'success':         True,
            'analysis_type':   'cpe_query',
            'cpe':             cpe,
            'total_cves':      stats['total_cves'],
            'vulnerabilities': cves[:100],
            'statistics':      stats,
            'data_source':     'NVD (direct CPE query)',
            'ai_analysis':     ai_analysis,
            'note':            f"Showing first 100 of {stats['total_cves']} CVEs"
                               if stats['total_cves'] > 100 else None,
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── /api/export-all ───────────────────────────────────────────────────────────

@app.route('/api/export-all', methods=['POST'])
def export_all():
    """Export ALL CVEs for a CPE (no pagination limit)."""
    data = request.get_json()
    if not data or 'cpe' not in data:
        return jsonify({'success': False, 'error': 'cpe is required'}), 400

    try:
        cves  = nvd_api.search_by_cpe(data['cpe'], max_results=None)
        stats = _calc_stats(cves)
        return jsonify({
            'success':         True,
            'cpe':             data['cpe'],
            'total_cves':      len(cves),
            'vulnerabilities': cves,
            'statistics':      stats,
            'data_source':     'NVD (complete export)',
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── /api/status ───────────────────────────────────────────────────────────────

@app.route('/api/status', methods=['GET'])
@app.route('/api/stats', methods=['GET'])
def get_status():
    sv = severity_status()
    return jsonify({
        'tool':             'Software Vulnerability Assessment Tool',
        'version':          '2.0',
        'nvd_api_key':      nvd_api.api_key is not None,
        'rate_limit':       '50 req/30s' if nvd_api.api_key else '5 req/30s',
        'ai_claude':        ai_available(),
        'sem_cpe_faiss':    sem_available(),
        'severity_pipeline': sv,
        'secbert_relevance': secbert_available(),
        'package_ecosystems': PackageAnalyzer.supported_filenames(),
        'features': {
            'pe_binary_analysis':        True,
            'package_manifest_analysis': True,
            'software_name_search':      True,
            'direct_cpe_query':          True,
            'ai_cpe_matching':           ai_available(),
            'ai_risk_narrative':         ai_available(),
            'severity_ml_ensemble':      sv['available'],
            'semantic_cve_relevance':    secbert_available(),
            'cwe_behavior_prediction':   True,   # Hướng 3 — always on
        },
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _calc_stats(cves: list) -> dict:
    if not cves:
        return {
            'total_cves': 0,
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0},
            'avg_cvss': 0,
            'max_cvss': 0,
            'min_cvss': 0,
        }

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0}
    for cve in cves:
        sev = cve.get('severity', 'NONE')
        counts[sev] = counts.get(sev, 0) + 1

    scores = [c.get('cvss_score', 0) for c in cves if (c.get('cvss_score') or 0) > 0]
    return {
        'total_cves':  len(cves),
        'by_severity': counts,
        'avg_cvss':    round(sum(scores) / len(scores), 2) if scores else 0,
        'max_cvss':    round(max(scores), 2) if scores else 0,
        'min_cvss':    round(min(scores), 2) if scores else 0,
    }


# ── Backward-compat alias (kept for any existing clients) ─────────────────────
@app.route('/api/pe-analyze', methods=['POST'])
@app.route('/api/scan', methods=['POST'])
def legacy_scan():
    """Backward-compatible alias → delegates to /api/analyze."""
    return analyze_file()


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print()
    print("Dashboard : http://localhost:5000")
    print()
    print("Endpoints :")
    print("  POST /api/analyze         - Analyze PE binary or package manifest")
    print("  POST /api/search          - Search by software name")
    print("  POST /api/query-cpe       - Query by CPE string")
    print("  POST /api/export-all      - Export ALL CVEs")
    print("  GET  /api/status          - System status")
    print()
    app.run(debug=True, host='0.0.0.0', port=5000)
