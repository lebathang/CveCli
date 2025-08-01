# cve_cli/services/rag_service.py
from openai import OpenAI # Thay đổi import
from cve_cli.core.config import XAI_API_KEY # Thay đổi import

# Khởi tạo client trỏ đến API của xAI
try:
    # Đây là điểm quan trọng: chỉ định base_url đến server của xAI
    client = OpenAI(
        api_key=XAI_API_KEY,
        base_url="https://api.x.ai/v1",
    )
except Exception as e:
    client = None
    print(f"Lỗi khởi tạo client: {e}")

def get_ai_solution(cve_id: str, cve_description: str) -> str:
    """
    Sử dụng API của xAI Grok để tạo ra giải pháp.
    """
    if not client:
        return "❌ Client chưa được khởi tạo. Vui lòng kiểm tra API key."

    # Prompt vẫn giữ nguyên vì nó được thiết kế tốt cho nhiệm vụ này
    prompt = f"""
    Hãy đóng vai một chuyên gia bảo mật. Dựa vào thông tin dưới đây về một lỗ hổng CVE, hãy cung cấp một bản phân tích và đề xuất giải pháp chi tiết.

    **CVE ID:** {cve_id}
    **Mô tả:** {cve_description}

    Vui lòng trình bày câu trả lời ngắn gọn, súc tích nhưng đầy đủ theo cấu trúc sau:
    1.  **Tóm tắt Nguy cơ:** Giải thích ngắn gọn nguy cơ chính của lỗ hổng này.
    2.  **Phân tích Tác động:** Ai hoặc hệ thống nào có thể bị ảnh hưởng?
    3.  **Các bước Giảm thiểu & Khắc phục:** Liệt kê các hành động cụ thể, ưu tiên các giải pháp chính thức như nâng cấp phiên bản.
    """

    print(f"[*] Đang gửi yêu cầu đến xAI (Grok) để phân tích {cve_id}...")

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="grok-4",  # Sử dụng model của xAI, ví dụ: grok-4 hoặc grok-3-mini
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        return f"❌ Đã xảy ra lỗi khi gọi API của xAI: {e}"