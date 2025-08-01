# cve_cli/services/nuclei_service.py
import subprocess
import json
from typing import List, Dict, Any

def run_nuclei_scan(target: str) -> Dict[str, Any]:
    """
    Chạy Nuclei để quét một mục tiêu và trả về kết quả.
    """
    # -silent: ẩn banner của Nuclei
    # -jsonl: output dưới dạng JSON Lines (mỗi dòng một object JSON)
    command = [
        "nuclei", 
        "-target", target, 
        "-jsonl",
        "-silent",
    ]
    
    try:
        # Thực thi lệnh
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        
        findings = []
        # Nuclei trả về JSON trên mỗi dòng, chúng ta cần đọc từng dòng
        for line in result.stdout.strip().splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                # Bỏ qua các dòng không phải JSON (nếu có)
                continue
                
        return {"findings": findings}

    except FileNotFoundError:
        return {"error": "Không tìm thấy 'nuclei'. Vui lòng cài đặt Nuclei và đảm bảo nó nằm trong PATH hệ thống."}
    except subprocess.CalledProcessError as e:
        # Nếu Nuclei không tìm thấy lỗ hổng, nó có thể thoát với mã lỗi. 
        # Chúng ta vẫn cần đọc stdout để xem có kết quả không.
        if e.stdout:
             # Cố gắng đọc kết quả ngay cả khi có lỗi
            findings = []
            for line in e.stdout.strip().splitlines():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return {"findings": findings}
        return {"error": f"Lỗi khi chạy Nuclei: {e.stderr}"}