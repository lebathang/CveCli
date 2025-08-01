# cve_cli/services/trivy_service.py
import subprocess
import json
from typing import Dict, Any

def run_trivy_scan(path_to_scan: str) -> Dict[str, Any]:
    """
    Chạy Trivy để quét một đường dẫn và trả về kết quả dưới dạng dictionary.
    """
    command = [
        "trivy", 
        "fs",        # Quét file system
        path_to_scan, 
        "--format", "json",
        "--quiet",   # Chỉ hiển thị output JSON
        "--scanners", "vuln" # Chỉ tập trung quét lỗ hổng
    ]
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        
        # Trivy có thể trả về nhiều dòng, dòng cuối cùng thường là JSON kết quả
        last_json_line = result.stdout.strip().splitlines()[-1]
        return json.loads(last_json_line)

    except FileNotFoundError:
        return {"error": "Không tìm thấy 'trivy'. Vui lòng cài đặt Trivy và đảm bảo nó nằm trong PATH hệ thống."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Lỗi khi chạy Trivy: {e.stderr}"}
    except (json.JSONDecodeError, IndexError):
        return {"error": "Không thể phân tích kết quả JSON từ Trivy. Có thể không có lỗ hổng nào được tìm thấy hoặc có lỗi xảy ra."}