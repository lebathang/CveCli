# cve_cli/services/nmap_service.py
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

def _parse_nmap_xml(xml_output: str) -> List[Dict[str, Any]]:
    """
    Phân tích output XML từ Nmap và chuyển thành một cấu trúc dữ liệu dễ sử dụng.
    """
    hosts_data = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            ip_address = host.find('address').get('addr')
            hostnames = [h.get('name') for h in host.findall('hostnames/hostname')]
            
            ports_data = []
            for port in host.findall('ports/port'):
                service = port.find('service')
                port_info = {
                    "port": port.get('portid'),
                    "protocol": port.get('protocol'),
                    "state": port.find('state').get('state'),
                    "service_name": service.get('name') if service is not None else 'unknown',
                    "product": service.get('product') if service is not None else '',
                    "version": service.get('version') if service is not None else ''
                }
                ports_data.append(port_info)

            hosts_data.append({
                "ip": ip_address,
                "hostnames": hostnames,
                "ports": ports_data
            })
    except ET.ParseError as e:
        print(f"Lỗi phân tích XML: {e}")
    
    return hosts_data

def run_nmap_scan(target: str, scan_type: str) -> Dict[str, Any]:
    """
    Chạy Nmap với một kiểu quét cụ thể và trả về kết quả đã được phân tích.
    """
    command = ["nmap"]
    
   # --- DANH SÁCH LỆNH QUÉT MỞ RỘNG ---
    scan_flags = {
        # Host Discovery
        "ping": ["-sn"],
        "list": ["-sL"],
        "no-ping": ["-Pn"],
        
        # Port Scanning Techniques
        "tcp-syn": ["-sS"],
        "tcp-connect": ["-sT"],
        "udp": ["-sU", "--top-ports", "200"], # Quét 200 cổng UDP phổ biến
        "fin": ["-sF"],
        "xmas": ["-sX"],
        "null": ["-sN"],
        
        # Service/Version/OS Detection
        "version": ["-sV"],
        "os-detect": ["-O"],
        "aggressive": ["-A"],
        
        # NSE Scripts
        "script-vuln": ["--script", "vuln"],
        "script-default": ["-sC"],
        
        # Default
        "default": ["-T4", "-F"] # Quét nhanh 100 cổng phổ biến
    }

    command.extend(scan_flags.get(scan_type, scan_flags["default"]))
        
    # Yêu cầu output dạng XML ra stdout
    command.extend(["-oX", "-", target])
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        
        parsed_data = _parse_nmap_xml(result.stdout)
        return {"scan_data": parsed_data}

    except FileNotFoundError:
        return {"error": "Không tìm thấy 'nmap'. Vui lòng cài đặt Nmap và đảm bảo nó nằm trong PATH hệ thống."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Lỗi khi chạy Nmap: {e.stderr}"}