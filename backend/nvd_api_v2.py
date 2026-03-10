# backend/nvd_api_v2.py

"""
NVD API Client V2 - Direct CPE Query
Query CVEs directly from NVD API by CPE (không qua junction.csv)
Official NVD API: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
import time
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import quote

class NVDAPIv2:
    """Direct NVD API query by CPE"""
    
    def __init__(self, api_key=None):
        """
        Initialize NVD API client
        
        Args:
            api_key: NVD API key (paste trực tiếp hoặc từ environment)
        """
        # ====================================================================
        # 🔑 GÁN API KEY TRỰC TIẾP TẠI ĐÂY
        # ====================================================================
        # Bỏ comment và paste API key của bạn:
        # self.api_key = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        self.api_key = "0716c34c-ae5d-4cca-a01d-ef86173b304d"  # Hoặc truyền vào khi khởi tạo
        # ====================================================================
        
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting
        self.last_request_time = 0
        if self.api_key:
            self.request_delay = 0.6  # 50 requests / 30s
            print(f"[NVD API v2] [+] API key detected - Rate: 50 req/30s")
        else:
            self.request_delay = 6.0  # 5 requests / 30s
            print(f"[NVD API v2] [!] No API key - Rate: 5 req/30s (SLOW!)")
            print(f"[NVD API v2] [i] Get key: https://nvd.nist.gov/developers/request-an-api-key")
        
        # Cache
        self.cache_dir = Path("data/cache/nvd_v2")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def search_by_cpe(self, cpe_name, results_per_page=100, max_results=None):
        """
        Search CVEs by CPE name - DIRECT từ NVD API
        
        Args:
            cpe_name: CPE string (e.g., "cpe:2.3:o:linux:linux_kernel:2.6.20.6:*:*:*:*:*:*:*")
            results_per_page: Number of results per page (max 2000)
            max_results: Maximum total results (None = all)
            
        Returns:
            List of CVE objects
        """
        
        print(f"\n[NVD Search] CPE: {cpe_name}")
        print(f"[NVD Search] Querying NVD API directly...")
        
        all_cves = []
        start_index = 0
        total_results = None
        
        while True:
            # Rate limiting
            self._rate_limit()
            
            # Build request
            params = {
                'cpeName': cpe_name,
                'resultsPerPage': min(results_per_page, 2000),  # NVD max = 2000
                'startIndex': start_index
            }
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            try:
                print(f"[NVD Search] Fetching results {start_index}-{start_index + results_per_page}...", end='\r')
                
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                response.raise_for_status()
                data = response.json()
                
                # Get total results from first response
                if total_results is None:
                    total_results = data.get('totalResults', 0)
                    print(f"\n[NVD Search] [+] Found {total_results:,} total CVEs in NVD")

                    if total_results == 0:
                        print(f"[NVD Search] [!] No CVEs found for this CPE")
                        return []
                
                # Parse vulnerabilities
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln)
                    all_cves.append(cve_data)
                
                # Check if we should continue
                start_index += len(vulnerabilities)
                
                # Stop if we've fetched all results
                if start_index >= total_results:
                    break
                
                # Stop if we hit max_results limit
                if max_results and len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    print(f"\n[NVD Search] [!] Reached max_results limit: {max_results}")
                    break
                
                # Stop if no more results in this page
                if len(vulnerabilities) == 0:
                    break
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    print(f"\n[NVD Search] [ERROR] Error 403: Invalid API key or rate limit exceeded")
                elif e.response.status_code == 404:
                    print(f"\n[NVD Search] [ERROR] Error 404: CPE not found")
                else:
                    print(f"\n[NVD Search] [ERROR] HTTP Error: {e}")
                break

            except Exception as e:
                print(f"\n[NVD Search] [ERROR] Error: {e}")
                break

        print(f"\n[NVD Search] [+] Fetched {len(all_cves):,} CVEs successfully")
        
        return all_cves
    
    def search_by_keyword(self, keyword, results_per_page=100, max_results=50):
        """
        Search CVEs by keyword using NVD keywordSearch parameter.
        Used as fallback when CPE-based search returns 0 results.

        Args:
            keyword: Software name or search term
            results_per_page: Number of results per page (max 2000)
            max_results: Maximum total results to return

        Returns:
            List of CVE objects
        """
        print(f"\n[NVD Search] Keyword fallback: '{keyword}'")

        all_cves = []
        start_index = 0
        total_results = None

        while True:
            self._rate_limit()

            params = {
                'keywordSearch': keyword,
                'resultsPerPage': min(results_per_page, 2000),
                'startIndex': start_index,
            }

            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()

                if total_results is None:
                    total_results = data.get('totalResults', 0)
                    print(f"[NVD Search] [+] Keyword search found {total_results:,} CVEs")
                    if total_results == 0:
                        return []

                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln)
                    cve_data['search_method'] = 'keyword'
                    all_cves.append(cve_data)

                start_index += len(vulnerabilities)

                if start_index >= total_results:
                    break
                if max_results and len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    break
                if len(vulnerabilities) == 0:
                    break

            except requests.exceptions.HTTPError as e:
                print(f"\n[NVD Search] [ERROR] Keyword search HTTP error: {e}")
                break
            except Exception as e:
                print(f"\n[NVD Search] [ERROR] Keyword search error: {e}")
                break

        print(f"[NVD Search] [+] Keyword search returned {len(all_cves)} CVEs")
        return all_cves

    def _parse_cve(self, vuln_data):
        """Parse NVD vulnerability data - EXACT format"""
        
        cve = vuln_data.get('cve', {})
        
        # CVE ID
        cve_id = cve.get('id', 'N/A')
        
        # Description (English)
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # CVSS Metrics
        metrics = cve.get('metrics', {})
        
        cvss_score = 0.0
        severity = 'NONE'
        vector_string = ''
        cvss_version = ''
        exploitability = None
        impact = None
        
        # CVSS v3.1 (Priority 1)
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            metric = metrics['cvssMetricV31'][0]
            cvss_data = metric.get('cvssData', {})
            
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            severity = cvss_data.get('baseSeverity', 'NONE')
            vector_string = cvss_data.get('vectorString', '')
            cvss_version = 'CVSS v3.1'
            
            exploitability = metric.get('exploitabilityScore')
            impact = metric.get('impactScore')
        
        # CVSS v3.0 (Priority 2)
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            metric = metrics['cvssMetricV30'][0]
            cvss_data = metric.get('cvssData', {})
            
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            severity = cvss_data.get('baseSeverity', 'NONE')
            vector_string = cvss_data.get('vectorString', '')
            cvss_version = 'CVSS v3.0'
            
            exploitability = metric.get('exploitabilityScore')
            impact = metric.get('impactScore')
        
        # CVSS v2 (Priority 3)
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            metric = metrics['cvssMetricV2'][0]
            cvss_data = metric.get('cvssData', {})
            
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            cvss_version = 'CVSS v2.0'
            
            # Map v2 score to severity
            if cvss_score >= 7.0:
                severity = 'HIGH'
            elif cvss_score >= 4.0:
                severity = 'MEDIUM'
            elif cvss_score > 0:
                severity = 'LOW'
            
            vector_string = cvss_data.get('vectorString', '')
            
            exploitability = metric.get('exploitabilityScore')
            impact = metric.get('impactScore')
        
        # Dates
        published = cve.get('published', '')
        modified = cve.get('lastModified', '')
        
        # Format dates
        if published:
            try:
                dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
                published = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        if modified:
            try:
                dt = datetime.fromisoformat(modified.replace('Z', '+00:00'))
                modified = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        # References
        references = []
        for ref in cve.get('references', []):
            url = ref.get('url', '')
            if url and url not in references:
                references.append(url)
        
        # CPEs
        cpes = []
        configurations = cve.get('configurations', [])
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable', True):
                        cpe_uri = cpe_match.get('criteria', '')
                        if cpe_uri and cpe_uri not in cpes:
                            cpes.append(cpe_uri)
        
        # Weaknesses (CWE)
        weaknesses = []
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe = desc.get('value', '')
                    if cwe and cwe not in weaknesses:
                        weaknesses.append(cwe)
        
        source_identifier = cve.get('sourceIdentifier', 'Unknown')
        
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'severity': severity,
            'vector_string': vector_string,
            'cvss_version': cvss_version,
            'published': published,
            'modified': modified,
            'references': references,
            'cpes': cpes,
            'weaknesses': weaknesses,
            'exploitability_score': exploitability,
            'impact_score': impact,
            'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve_id},",
            'cna': cve.get('sourceIdentifier', 'Unknown')
        }
    
    def search_by_cwe(self, cwe_id: str, max_results: int = 20) -> list:
        """
        Search CVEs by CWE ID — used by Hướng 3 (CWE behavior prediction).

        NVD API parameter: cweId (e.g. "CWE-94", "CWE-78")
        Returns CVEs that have been classified under the given weakness type.

        Args:
            cwe_id:      CWE identifier string, e.g. "CWE-94"
            max_results: Maximum number of CVEs to return

        Returns:
            List of CVE dicts (same format as search_by_cpe / search_by_keyword)
        """
        print(f"\n[NVD Search] CWE query: {cwe_id} (max {max_results})")

        all_cves: list = []
        start_index    = 0
        total_results  = None

        while True:
            self._rate_limit()

            params = {
                "cweId":          cwe_id,
                "resultsPerPage": min(max_results, 2000),
                "startIndex":     start_index,
            }
            headers = {"apiKey": self.api_key} if self.api_key else {}

            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    print(f"[NVD Search] [+] {cwe_id}: {total_results:,} total CVEs in NVD")
                    if total_results == 0:
                        return []

                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln)
                    cve_data["search_method"] = "cwe"
                    all_cves.append(cve_data)

                start_index += len(vulnerabilities)

                if start_index >= total_results:
                    break
                if len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    break
                if not vulnerabilities:
                    break

            except requests.exceptions.HTTPError as e:
                print(f"\n[NVD Search] [ERROR] CWE search HTTP error: {e}")
                break
            except Exception as e:
                print(f"\n[NVD Search] [ERROR] CWE search error: {e}")
                break

        print(f"[NVD Search] [+] CWE {cwe_id}: returned {len(all_cves)} CVEs")
        return all_cves

    def _rate_limit(self):
        """Enforce rate limiting"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time

        if elapsed < self.request_delay:
            sleep_time = self.request_delay - elapsed
            time.sleep(sleep_time)

        self.last_request_time = time.time()


# Quick test
if __name__ == "__main__":
    print("=" * 80)
    print("[*] TESTING NVD API V2 - Direct CPE Query")
    print("=" * 80)
    print()
    
    # Test CPE
    test_cpe = "cpe:2.3:o:linux:linux_kernel:2.6.20.6:*:*:*:*:*:*:*"
    
    print(f"Test CPE: {test_cpe}")
    print(f"Expected: ~3918 CVEs (from NVD website)")
    print()
    
    # Initialize API
    api = NVDAPIv2()
    
    # Search (limit to 10 for test)
    print("Searching first 10 CVEs...")
    cves = api.search_by_cpe(test_cpe, max_results=10)
    
    print()
    print("=" * 80)
    print("[*] RESULTS")
    print("=" * 80)
    print()
    
    print(f"Total fetched: {len(cves)} CVEs")
    print()
    
    if cves:
        print("Top 5 CVEs by CVSS:")
        sorted_cves = sorted(cves, key=lambda x: x['cvss_score'], reverse=True)
        
        for i, cve in enumerate(sorted_cves[:5], 1):
            print(f"{i}. {cve['cve_id']}")
            print(f"   Severity: {cve['severity']}")
            print(f"   CVSS: {cve['cvss_score']} ({cve['cvss_version']})")
            print(f"   Published: {cve['published']}")
            print(f"   URL: {cve['nvd_url']}")
            print()