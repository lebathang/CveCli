# cve_cli/services/elastic_service.py
import re
import time
import requests
from rich.console import Console

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _is_cve_id_format(keyword: str) -> bool:
    """Kiểm tra xem từ khóa có định dạng của một ID CVE hay không."""
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', keyword, re.IGNORECASE))

# --- THAY ĐỔI: Thêm tham số exact_score ---
def search_cves(keyword: str, console: Console, min_cvss: float = 0.0, exact_score: float = None) -> list:
    """
    Tìm kiếm và lấy TOÀN BỘ CVE từ API của NIST.
    """
    all_vulnerabilities = []
    start_index = 0
    results_per_page = 2000
    total_results_known = 0
    
    while True:
        params = {'resultsPerPage': results_per_page, 'startIndex': start_index}
        if _is_cve_id_format(keyword):
            params['cveId'] = keyword
        else:
            params['keywordSearch'] = keyword

        try:
            status_text = f"Đang tải kết quả... Đã tìm thấy {len(all_vulnerabilities)}/{total_results_known or '??'} CVE"
            with console.status(f"[bold green]{status_text}[/bold green]", spinner="dots"):
                response = requests.get(NVD_API_URL, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()

            vulnerabilities_in_batch = [item['cve'] for item in data.get('vulnerabilities', [])]
            all_vulnerabilities.extend(vulnerabilities_in_batch)
            
            if start_index == 0:
                total_results_known = data.get('totalResults', 0)

            start_index += results_per_page
            if start_index >= total_results_known or 'cveId' in params:
                break
            time.sleep(1) 

        except requests.exceptions.RequestException as e:
            console.print(f"❌ Lỗi khi gọi API: {e}")
            return []
            
    # --- THAY ĐỔI: Cập nhật logic lọc ---
    if exact_score is not None or min_cvss > 0.0:
        filtered_results = []
        for cve in all_vulnerabilities:
            base_score = 0.0
            metrics = cve.get("metrics", {}).get("cvssMetricV31")
            if metrics:
                base_score = metrics[0].get("cvssData", {}).get("baseScore", 0.0)
            
            # Ưu tiên lọc theo điểm chính xác
            if exact_score is not None:
                if base_score == exact_score:
                    filtered_results.append(cve)
            # Nếu không, lọc theo điểm tối thiểu
            elif min_cvss > 0.0:
                if base_score >= min_cvss:
                    filtered_results.append(cve)
        return filtered_results

    return all_vulnerabilities