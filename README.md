# CVECLI

![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ⚙️ Cài Đặt & Cấu Hình

1.  **Clone repository:**
    ```bash
    git clone https://github.com/lebathang/CveCli.git
    ```

2.  **Tạo và kích hoạt môi trường ảo:**

    ```bash
    python -m venv .venv
    # Trên Windows
    .\.venv\Scripts\activate
    # Trên macOS/Linux
    source .venv/bin/activate
    ```

3.  **Cài đặt các thư viện Python:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Cấu hình API Keys và Công cụ:**
    -   **AI (xAI Grok):** Tạo một file tên là `.env` trong thư mục gốc, sao chép nội dung từ `.env.example` và thêm API key của bạn vào:
        ```
        XAI_API_KEY="Your-xAI-Secret-Key-Here"
        ```
    -   **Snyk:** Chạy lệnh sau để xác thực Snyk CLI với tài khoản của bạn:
        ```bash
        snyk auth
        ```
    -   **Nuclei:** Cập nhật bộ template mới nhất:
        ```bash
        nuclei -update-templates
        ```

## 🛠️ Yêu Cầu Cài Đặt (Prerequisites)

Trước khi cài đặt, bạn cần đảm bảo các công cụ sau đã được cài đặt trên hệ thống và có thể được gọi từ dòng lệnh:

-   **Python** (phiên bản 3.9 trở lên)
-   **Nmap:** Công cụ quét mạng. ([Trang chủ](https://nmap.org/download.html))
-   **Nuclei:** Công cụ quét lỗ hổng dựa trên template. ([Trang chủ](https://nuclei.projectdiscovery.io/nuclei/install/))
-   **Trivy:** Công cụ quét lỗ hổng. ([Trang chủ](https://aquasecurity.github.io/trivy/latest/getting-started/installation/))
-   **Snyk CLI:** Công cụ quét phụ thuộc. ([Trang chủ](https://docs.snyk.io/snyk-cli/install-the-snyk-cli))

## 🚀 Hướng Dẫn Sử Dụng
Tất cả các lệnh đều được chạy từ thư mục gốc của dự án.

### 1. Xem hướng dẫn sử dụng

```Bash

python -m cve_cli.cli --help
```

### 2. Tìm kiếm CVE (`search`)

Tìm theo ID cụ thể:

```Bash

python -m cve_cli.cli search "CVE-2024-27198"
```

Tìm theo từ khóa bất kỳ:

```Bash

python -m cve_cli.cli search "API security"
```

Tìm theo từ khóa với bộ lọc CVSS:

Kết quả sẽ được phân trang, sử dụng n (next), p (previous), và q (quit) để điều hướng.


```Bash

python -m cve_cli.cli search "SQL Injection" --min-score 9.0
```

Tìm tất cả CVE có từ khóa "API" và điểm CVSS chính xác là 9.8

```Bash

python -m cve_cli.cli search "API" --exact-score 9.8
```


### 3. Lấy Giải pháp bằng AI (solution)

tìm giải pháp CVE bằng trí tuệ nhân tạo

```Bash

python -m cve_cli.cli solution CVE-2023-34048
```


---
> [!NOTE]  
Dưới đây là danh sách các công cụ quét CVE hiệu quả được tích hợp và điều khiển trực tiếp bằng thư viện `subprocess` của Python. Các công cụ này đều có giao diện dòng lệnh (CLI) mạnh mẽ, được thiết kế cho mục đích tự động hóa.



### Quét Mạng & Hạ tầng (Network & Infrastructure)

| Tên Công Cụ | Mục Đích Chính | Lệnh Ví dụ cho `subprocess` |
| :--- | :--- | :--- |
| **Nmap** | Khám phá mạng, quét cổng và phát hiện dịch vụ. Có thể dùng script (NSE) để tìm CVE. | `['nmap', '-sV', '--script=vuln', 'target.com']` |

---

### Quét Phụ thuộc, Mã nguồn & Container

| Tên Công Cụ | Mục Đích Chính | Lệnh Ví dụ cho `subprocess` |
| :--- | :--- | :--- |
| **Trivy** | Quét lỗ hổng trong container image, filesystem, và các thư viện mã nguồn mở. | `['trivy', 'image', 'python:3.9-slim']` |
| **Snyk** | Quét CVE trong mã nguồn, thư viện, file cấu hình IaC và container. | `['snyk', 'test', '--all-projects']` |
---

### Quét Ứng dụng Web & API

| Tên Công Cụ | Mục Đích Chính | Lệnh Ví dụ cho `subprocess` |
| :--- | :--- | :--- |
| **Nuclei** | Quét lỗ hổng web, API, và dịch vụ dựa trên các template có sẵn. Cực kỳ nhanh. | `['nuclei', '-u', 'https://example.com']` |


## Hướng dẫn dùng Nmap

Nếu bạn chưa có Nmap, hãy cài đặt nó trước. Nmap có sẵn cho mọi hệ điều hành.

Trang chủ: https://nmap.org/download.html

Hãy chắc chắn rằng lệnh nmap có thể được gọi từ bất kỳ đâu trong terminal của bạn (tức là nó đã được thêm vào PATH hệ thống).


Quét nhanh (mặc định):
```Bash

python -m cve_cli.cli nmap-scan scanme.nmap.org
```

Quét phiên bản dịch vụ:

```Bash

python -m cve_cli.cli nmap-scan scanme.nmap.org --type version
```

Quét hệ điều hành (cần quyền root/admin):

```Bash

sudo python -m cve_cli.cli nmap-scan scanme.nmap.org --type os-detect
```

Quét toàn diện (cần quyền root/admin):

```Bash

sudo python -m cve_cli.cli nmap-scan scanme.nmap.org -t aggressive
```

```Bash
# Thay bằng dải mạng của bạn`
python -m cve_cli.cli nmap-scan 192.168.1.0/24 --ping
```

Quét sâu để tìm phiên bản dịch vụ:

```Bash

python -m cve_cli.cli nmap-scan scanme.nmap.org --version
```
Quét TCP SYN (cần quyền root):

```Bash

sudo python -m cve_cli.cli nmap-scan scanme.nmap.org -t tcp-syn
```
Quét các cổng UDP phổ biến:

```Bash

sudo python -m cve_cli.cli nmap-scan scanme.nmap.org -t udp
```
Chạy các script mặc định của Nmap:

```Bash

python -m cve_cli.cli nmap-scan scanme.nmap.org -t script-default
```

## Hướng dẫn dùng Trivy
Nếu bạn chưa cài đặt, hãy làm theo hướng dẫn tại trang chủ của Trivy để cài đặt nó trên hệ thống của bạn: Trivy Installation Guide. 


## hướng dẫn dùng Nuclei 
Trước hết, bạn cần cài đặt Nuclei và bộ template của nó.

Cài đặt Nuclei: Truy cập trang hướng dẫn chính thức và làm theo các bước cho hệ điều hành của bạn: Nuclei Installation Guide.

Cập nhật Templates: Sau khi cài đặt, hãy chạy lệnh sau để tải về bộ template quét mới nhất (rất quan trọng):

```Bash

nuclei -update-templates
```
```Bash 

python -m cve_cli.cli nuclei-scan http://scanme.nmap.org
```

## Hướng dẫn dùng Snyk 
Tạo tài khoản Snyk: Đăng ký một tài khoản miễn phí tại https://snyk.io/.

Cài đặt Snyk CLI: Bạn cần có Node.js và npm. Sau đó chạy lệnh:

```Bash

npm install -g snyk
```

Xác thực tài khoản: Chạy lệnh sau và làm theo hướng dẫn trên trình duyệt để kết nối CLI với tài khoản của bạn.

```Bash

snyk auth
```
Chạy lệnh snyk-scan

```Bash

# Quét thư mục hiện tại`
python -m cve_cli.cli snyk-scan .

# Hoặc chỉ định một thư mục khác
# python -m cve_cli.cli snyk-scan /duong/dan/den/project/khac
```
---
🤝 Đóng Góp
Mọi đóng góp đều được chào đón! Vui lòng tạo Pull Request hoặc mở một Issue để thảo luận về những thay đổi bạn muốn thực hiện.

📄 Giấy Phép
Dự án này được cấp phép dưới Giấy phép MIT. Xem file LICENSE để biết thêm chi tiết.