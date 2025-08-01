# cve_cli/core/config.py

# Trong một dự án thực tế, file này sẽ chứa các cấu hình quan trọng như:
# - API keys cho các dịch vụ LLM (OpenAI, Google AI)
# - URL và thông tin xác thực cho Elasticsearch và Vector Database
# - Các cài đặt khác của ứng dụng

import os
from dotenv import load_dotenv

# Tải các biến môi trường từ file .env
load_dotenv()

APP_NAME = "CVE AI Search Tool"
XAI_API_KEY = os.getenv("XAI_API_KEY") # Đổi sang biến mới

if not XAI_API_KEY:
    print("Lỗi: Không tìm thấy XAI_API_KEY. Vui lòng tạo file .env và thêm key vào.")