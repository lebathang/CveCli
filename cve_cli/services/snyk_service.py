# cve_cli/services/snyk_service.py
import subprocess
import json
from typing import Dict, Any

def run_snyk_scan(path: str) -> Dict[str, Any]:
    """
    Chạy 'snyk test' trên một đường dẫn và trả về kết quả đã được phân tích.
    """
    # Lệnh để chạy Snyk và yêu cầu output dạng JSON
    command = [
        "snyk", 
        "test", 
        path, 
        "--json"
    ]
    
    try:
        # Snyk trả về mã lỗi > 0 nếu tìm thấy lỗ hổng.
        # Do đó, chúng ta không dùng check=True mà sẽ kiểm tra mã lỗi sau.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        
        # Phân tích kết quả JSON từ stdout
        # Snyk có thể trả về một object hoặc một mảng object JSON
        scan_data = json.loads(result.stdout)
        
        # Chuẩn hóa để luôn làm việc với một danh sách
        if not isinstance(scan_data, list):
            scan_data = [scan_data]

        return {"results": scan_data}

    except FileNotFoundError:
        return {"error": "Không tìm thấy 'snyk'. Vui lòng cài đặt Snyk CLI và đảm bảo nó nằm trong PATH hệ thống."}
    except json.JSONDecodeError:
        # Lỗi này có thể xảy ra nếu Snyk báo lỗi không phải dạng JSON (ví dụ: chưa xác thực)
        return {"error": f"Không thể phân tích kết quả JSON từ Snyk. Bạn đã chạy 'snyk auth' chưa? Lỗi gốc: {result.stderr}"}
    except Exception as e:
        return {"error": f"Đã xảy ra lỗi không xác định: {e}"}