# cve_cli/cli.py

from enum import Enum
import typer
import math
from typing_extensions import Annotated

# Import các thành phần từ 'rich'
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
# Import các dịch vụ quét và tìm kiếm
from rich import print as rprint
from zmq import Enum

from cve_cli.services.elastic_service import search_cves
from cve_cli.services.rag_service import get_ai_solution
from cve_cli.services.nmap_service import run_nmap_scan
from cve_cli.services.snyk_service import run_snyk_scan
from cve_cli.services.trivy_service import run_trivy_scan
from cve_cli.services.nuclei_service import run_nuclei_scan

# Khởi tạo console của rich
console = Console()

# --- CẬP NHẬT: Thêm mô tả chi tiết và epilog cho ứng dụng ---
app = typer.Typer(
    name="SecTool",
    help="🤖 **Một công cụ dòng lệnh mạnh mẽ để tìm kiếm, phân tích và quét lỗ hổng CVE.**",
    rich_markup_mode="markdown",
    epilog="Phát triển bởi Th4n6_n3k. Sử dụng `[COMMAND] --help` để xem chi tiết."
)

# --- MỚI: Hàm hiển thị banner chào mừng ---
def display_welcome_banner():
    """Hiển thị một banner chào mừng đẹp mắt khi chạy tool."""
    console.clear()
    title = Align.center(
        Text("🛡️  CVE Client Toolkit  🛡️", style="bold magenta"),
        vertical="middle"
    )
    
    panel = Panel(
        title,
        title_align="center",
        subtitle="[dim]Gõ --help để xem các lệnh[/dim]",
        subtitle_align="center",
        border_style="green",
        padding=(1, 4)
    )
    console.print(panel)
    console.print(Align.center("[bold]Chào mừng bạn đến với bộ công cụ CVE dòng lệnh![/bold]"))
    console.print(Align.center("Dưới đây là các lệnh có sẵn:"))

# --- MỚI: Hàm callback chính, chạy trước mỗi lệnh ---
@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    Hàm callback chính của ứng dụng.
    Sẽ hiển thị banner nếu không có lệnh nào được gọi.
    """
    if ctx.invoked_subcommand is None:
        display_welcome_banner()
        # Tự động tạo và hiển thị lại danh sách lệnh
        console.print(ctx.get_help())


# --- ĐỊNH NGHĨA LỚP NmapScanType TẠI ĐÂY ---
class NmapScanType(str, Enum):
    # Nhóm Host Discovery
    ping = "ping"
    list_scan = "list"
    no_ping = "no-ping"
    # Nhóm Port Scanning
    default = "default"
    tcp_syn = "tcp-syn"
    tcp_connect = "tcp-connect"
    udp = "udp"
    fin = "fin"
    xmas = "xmas"
    null = "null"
    # Nhóm Service, OS, Version
    version = "version"
    os_detect = "os-detect"
    aggressive = "aggressive"
    # Nhóm Scripting
    script_vuln = "script-vuln"
    script_default = "script-default"

def display_cve_details(cve: dict):
    """Hàm phụ để hiển thị chi tiết một CVE trong một Panel."""
    content = Text()
    cve_id = cve.get('id', 'N/A')
    
    published_date = cve.get('published', 'N/A')
    modified_date = cve.get('lastModified', 'N/A')
    content.append(f"Published: {published_date} | Last Modified: {modified_date}\n\n", style="white")

    content.append("Mô tả:\n", style="bold")
    description_text = ""
    for desc_item in cve.get("descriptions", []):
        if desc_item.get("lang") == "en":
            description_text = desc_item.get("value", "N/A")
            break
    content.append(f"  {description_text}\n\n")

    metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
    if metrics:
        cvss_data = metrics.get('cvssData', {})
        score = cvss_data.get('baseScore', 'N/A')
        severity = cvss_data.get('baseSeverity', 'N/A')
        vector = cvss_data.get('vectorString', 'N/A')
        severity_color = "red" if severity == 'CRITICAL' else "yellow" if severity == 'HIGH' else "white"
        content.append("CVSS Metrics (V3.1):\n", style="bold")
        content.append(f"  - Score: ", style="white")
        content.append(f"{score} ({severity})\n", style=f"bold {severity_color}")
        content.append(f"  - Vector: {vector}\n\n")

    panel = Panel(
        content,
        title=f"[bold cyan]{cve_id}[/bold cyan]",
        border_style="blue",
        expand=True
    )
    console.print(panel)

# THAY THẾ HOÀN TOÀN HÀM SEARCH
@app.command(name="search", help="🔎 Tìm kiếm thông tin CVE theo từ khóa hoặc ID.")
def search(
    keyword: Annotated[str, typer.Argument(help="Từ khóa hoặc ID để tìm kiếm CVE.")],
    min_score: Annotated[float, typer.Option("--min-score", help="Lọc CVE có điểm từ mức này trở lên.")] = 0.0,
    exact_score: Annotated[float, typer.Option("--exact-score", help="Lọc CVE có điểm chính xác bằng mức này.")] = None
):
    """
    Tìm kiếm TOÀN BỘ CVE và hiển thị kết quả theo từng trang.
    """
    all_results = search_cves(keyword=keyword, console=console)

    if not all_results:
        console.print("[yellow]Không tìm thấy CVE nào phù hợp.[/yellow]")
        return

    total_results = len(all_results)
    results_per_page = 20
    total_pages = math.ceil(total_results / results_per_page)
    current_page = 1

    while True:
        console.clear()
        console.print(f"[bold green]✅ Tìm thấy {total_results} kết quả. Đang hiển thị trang {current_page}/{total_pages}.[/bold green]")
        
        start_index = (current_page - 1) * results_per_page
        end_index = start_index + results_per_page
        page_results = all_results[start_index:end_index]

        for cve in page_results:
            display_cve_details(cve)

        if total_pages <= 1:
            break

        console.print("\n[bold]Điều hướng:[/bold]")
        console.print("[cyan]n[/cyan] - Trang tiếp theo | [cyan]p[/cyan] - Trang trước | [cyan]q[/cyan] - Thoát")
        
        action = typer.prompt("Nhập lựa chọn của bạn").lower()

        if action == 'n':
            if current_page < total_pages:
                current_page += 1
        elif action == 'p':
            if current_page > 1:
                current_page -= 1
        elif action == 'q':
            break
        else:
            console.print("[red]Lựa chọn không hợp lệ.[/red]")
            typer.prompt("Nhấn Enter để tiếp tục...")



# THAY THẾ HOÀN TOÀN HÀM SOLUTION
@app.command(name="solution", help="💡 Tìm giải pháp cho một CVE bằng AI.")
def solution(
    cve_id: Annotated[str, typer.Argument(help="Mã CVE cần tìm giải pháp. Ví dụ: CVE-2021-44228")]
):
    """
    Lấy giải pháp do AI đề xuất cho một mã CVE cụ thể.
    """
    console.print(f"[*] Đang tìm thông tin chi tiết cho {cve_id}...")
    cve_results = search_cves(keyword=cve_id, console=console)
    
    if not cve_results:
        console.print(f"[bold red]Lỗi: Không tìm thấy thông tin cho {cve_id} trong cơ sở dữ liệu.[/bold red]")
        raise typer.Exit()
        
    cve_info = cve_results[0]
    cve_description = cve_info.get("description", "Không có mô tả.")
    
    ai_solution = ""
    # --- THÊM HIỆU ỨNG LOADING ---
    with console.status("[bold green]🧠 AI đang phân tích, vui lòng chờ...[/bold green]", spinner="dots"):
        # Gọi hàm AI bên trong khối 'status'
        ai_solution = get_ai_solution(cve_id=cve_id, cve_description=cve_description)
    # -----------------------------

    # Đóng khung kết quả của AI
    console.print(
        Panel(
            ai_solution, 
            title=f"[bold green]✨ Phân tích của AI cho {cve_id} ✨[/bold green]", 
            border_style="green"
        )
    )


# --- LỆNH MỚI: SCAN TRIVYs ---
@app.command(name="trivy-scan", help="🔬 Quét lỗ hổng trong file hoặc thư mục bằng Trivy.")
def trivy_scan_command(
    path: Annotated[str, typer.Argument(help="Đường dẫn đến file hoặc thư mục cần quét.")]
):
    """
    🔬  Quét lỗ hổng trong file hoặc thư mục bằng Trivy.
    """
    scan_results = None
    with console.status("[bold yellow]🚀 Đang chạy Trivy để quét...[/bold yellow]", spinner="dots"):
        scan_results = run_trivy_scan(path)

    if not scan_results or "error" in scan_results:
        error_msg = scan_results.get("error", "Lỗi không xác định.")
        console.print(f"[bold red]Lỗi: {error_msg}[/bold red]")
        raise typer.Exit()

    if not scan_results.get("Results"):
        console.print("[bold green]✅ Tuyệt vời! Trivy không tìm thấy lỗ hổng nào.[/bold green]")
        return

    for res in scan_results["Results"]:
        if not res.get("Vulnerabilities"):
            continue

        target = res.get("Target")
        console.print(f"\n[bold]Báo cáo cho: {target}[/bold]")
        
        table = Table(title="Lỗ hổng được phát hiện bởi Trivy")
        table.add_column("CVE ID", style="cyan", no_wrap=True)
        table.add_column("Gói thư viện", style="magenta")
        table.add_column("Phiên bản", style="green")
        table.add_column("Mức độ", style="red")
        
        for vuln in res["Vulnerabilities"]:
            table.add_row(
                vuln.get("VulnerabilityID"),
                vuln.get("PkgName"),
                vuln.get("InstalledVersion"),
                vuln.get("Severity")
            )
        
        console.print(table)

# --- LỆNH MỚI: NUCLEI-SCAN ---
@app.command(name="nuclei-scan", help="🛰️  Chạy quét lỗ hổng chủ động với Nuclei.")
def nuclei_scan_command(
    target: Annotated[str, typer.Argument(help="Mục tiêu để quét (URL, domain, hoặc IP).")]
):
    """
    Sử dụng công cụ Nuclei để thực hiện quét lỗ hổng tự động dựa trên
    các template được cộng đồng đóng góp.
    """
    scan_results = None
    with console.status(f"[bold yellow]🚀 Đang chạy Nuclei để quét {target}...[/bold yellow]", spinner="dots"):
        scan_results = run_nuclei_scan(target)

    if not scan_results or "error" in scan_results:
        error_msg = scan_results.get("error", "Lỗi không xác định.")
        console.print(f"[bold red]Lỗi: {error_msg}[/bold red]")
        raise typer.Exit()

    findings = scan_results.get("findings", [])
    if not findings:
        console.print(f"[bold green]✅ Tuyệt vời! Nuclei không tìm thấy lỗ hổng nào trên {target}.[/bold green]")
        return

    console.print(f"\n[bold red]🚨 Cảnh báo! Nuclei tìm thấy {len(findings)} phát hiện trên {target}:[/bold red]")

    table = Table(title=f"Báo cáo Quét Nuclei cho {target}")
    table.add_column("Template ID", style="cyan", no_wrap=True)
    table.add_column("Tên Lỗ hổng", style="magenta")
    table.add_column("Mức độ", style="red")
    table.add_column("URL được khớp", style="white")

    for finding in findings:
        info = finding.get("info", {})
        table.add_row(
            finding.get("template-id"),
            info.get("name"),
            info.get("severity"),
            finding.get("matched-at")
        )

    console.print(table)




# --- LỆNH MỚI: NMAP-SCAN ---
@app.command(name="nmap-scan", help="📡 Chạy quét mạng và cổng với Nmap.")
def nmap_scan_command(
    target: Annotated[str, typer.Argument(help="Mục tiêu để quét (URL, domain, IP, hoặc dải mạng).")],
    scan_type: Annotated[NmapScanType, typer.Option("--type", "-t", help="Loại quét Nmap cần thực hiện.")] = NmapScanType.default
):
    """
    Sử dụng công cụ Nmap với nhiều tùy chọn quét khác nhau.
    - **Host Discovery:** ping, list, no-ping.
    - **Port Scans:** default (top 100), tcp-syn, tcp-connect, udp, fin, xmas, null.
    - **Advanced:** version, os-detect, aggressive, script-vuln, script-default.
    """
    scan_results = None
    
    # Cảnh báo cho các kiểu quét cần quyền cao hoặc "ồn ào"
    if scan_type in [NmapScanType.tcp_syn, NmapScanType.os_detect, NmapScanType.aggressive]:
        console.print("[bold yellow]Cảnh báo: Kiểu quét này có thể cần quyền root/administrator để có kết quả chính xác.[/bold yellow]")

    with console.status(f"[bold yellow]🚀 Đang chạy Nmap (kiểu: {scan_type.value}) để quét {target}...[/bold yellow]", spinner="dots"):
        scan_results = run_nmap_scan(target, scan_type.value)

    if not scan_results or "error" in scan_results:
        error_msg = scan_results.get("error", "Lỗi không xác định.")
        console.print(f"[bold red]Lỗi: {error_msg}[/bold red]")
        raise typer.Exit()

    scan_data = scan_results.get("scan_data", [])
    if not scan_data:
        console.print(f"[bold green]✅ Hoàn tất. Nmap không tìm thấy thông tin nổi bật trên {target}.[/bold green]")
        return

    console.print(f"\n[bold green]📊 Kết quả quét Nmap cho {target}:[/bold green]")
    
    for host in scan_data:
        host_info = f"Host: {host['ip']}"
        if host['hostnames']:
            host_info += f" ({', '.join(host['hostnames'])})"
        
        console.print(f"\n[bold cyan]{host_info}[/bold cyan]")
        
        # Hiển thị thông tin OS nếu có
        if host.get('os'):
            console.print("\n  [bold]Hệ điều hành được phát hiện:[/bold]")
            for os_match in host['os']:
                console.print(f"    - {os_match['name']} (Chính xác: {os_match['accuracy']}%)")

        if not host.get('ports') and not host.get('scripts'):
            console.print("  -> Không có cổng hay script nào được phát hiện.")
            continue

        if host['ports']:
            table = Table(title="Các cổng được phát hiện")
            table.add_column("Port")
            table.add_column("State")
            table.add_column("Service")
            table.add_column("Product / Version")

            for port in host['ports']:
                version_info = f"{port['product']} {port['version']}".strip()
                table.add_row(
                    f"{port['port']}/{port['protocol']}",
                    port['state'],
                    port['service_name'],
                    version_info
                )
            console.print(table)

        if host.get('scripts'):
            console.print("\n  [bold]Kết quả từ Script Engine (NSE):[/bold]")
            for script in host['scripts']:
                console.print(f"    - [cyan]{script['id']}[/cyan]: {script['output'].strip()}")



# --- LỆNH MỚI: SNYK-SCAN ---
@app.command(name="snyk-scan", help="📦 Quét lỗ hổng trong các gói phụ thuộc với Snyk.")
def snyk_scan_command(
    path: Annotated[str, typer.Argument(help="Đường dẫn đến thư mục dự án cần quét.")] = "."
):
    """
    Sử dụng Snyk để quét các gói mã nguồn mở (open source) và tìm ra các
    lỗ hổng bảo mật đã biết trong các thư viện bạn đang dùng.
    """
    scan_output = None
    with console.status(f"[bold yellow]🚀 Đang chạy Snyk để quét '{path}'...[/bold yellow]", spinner="dots"):
        scan_output = run_snyk_scan(path)

    if not scan_output or "error" in scan_output:
        error_msg = scan_output.get("error", "Lỗi không xác định.")
        console.print(f"[bold red]Lỗi: {error_msg}[/bold red]")
        raise typer.Exit()

    total_vulns = 0
    results = scan_output.get("results", [])
    
    for res in results:
        # Kiểm tra xem Snyk có báo lỗi cho project này không
        if "error" in res:
            console.print(f"[bold red]Lỗi khi quét {res.get('path', path)}: {res['error']}[/bold red]")
            continue

        vulnerabilities = res.get("vulnerabilities", [])
        total_vulns += len(vulnerabilities)
        
        target_file = res.get("displayTargetFile", res.get("path"))
        console.print(f"\n[bold]Báo cáo cho: {target_file}[/bold]")

        if not vulnerabilities:
            console.print("[bold green]✅ Không tìm thấy lỗ hổng nào.[/bold green]")
            continue

        table = Table(title=f"Tìm thấy {len(vulnerabilities)} lỗ hổng")
        table.add_column("Snyk ID", style="cyan", no_wrap=True)
        table.add_column("Gói thư viện", style="magenta")
        table.add_column("Phiên bản", style="green")
        table.add_column("Mức độ", style="red")
        table.add_column("Tiêu đề", style="white")

        for vuln in vulnerabilities:
            table.add_row(
                vuln.get("id"),
                vuln.get("packageName"),
                vuln.get("version"),
                vuln.get("severity").capitalize(), # Viết hoa chữ cái đầu
                vuln.get("title")
            )
        console.print(table)
    
    if total_vulns > 0:
         console.print(f"\n[bold red]🚨 Tổng cộng tìm thấy {total_vulns} lỗ hổng.[/bold red]")



if __name__ == "__main__":
    app()
