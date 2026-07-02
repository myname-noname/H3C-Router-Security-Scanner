"""
通用工具模块 - IP/端口解析、格式化等
"""
import re
import socket
from typing import List, Tuple, Optional, Union


def parse_target(target: str) -> List[Tuple[str, int, bool]]:
    """
    解析目标字符串，返回 (ip, port, explicit_port) 列表

    explicit_port: 始终为 False（IP:端口格式不再支持）

    支持格式：
        - 192.168.1.1
        - 192.168.1.1-100
        - 192.168.1.0/24
        - 192.168.1.1,192.168.1.2
        - example.com

    注意：端口请在「扫描端口」输入框中单独指定，不支持在 IP 后加 :端口
    """
    results: List[Tuple[str, int, bool]] = []
    target = target.strip()

    # 逗号分隔处理
    parts = [p.strip() for p in target.split(",") if p.strip()]
    for part in parts:
        results.extend(_parse_single_target(part))

    return results


def _parse_single_target(target: str) -> List[Tuple[str, int, bool]]:
    """解析单个目标，返回 (ip, port, explicit_port)"""
    results = []

    # 去除端口部分（如果有 : 号，只取前面部分）
    ip_str = target.split(":")[0]

    # CIDR 格式
    if "/" in ip_str:
        ips = ip_range_from_cidr(ip_str)
    # 范围格式 192.168.1.1-100
    elif "-" in ip_str and ip_str.count(".") == 3:
        ips = ip_range_from_dash(ip_str)
    else:
        # 尝试解析域名
        ips = _resolve_host(ip_str)

    for ip in ips:
        # 使用默认端口列表
        for p in [80, 443, 8080, 8443]:
            results.append((ip, p, False))

    return results


def _resolve_host(host: str) -> List[str]:
    """解析主机名到 IP 地址列表"""
    # 如果是 IP 地址，直接返回
    if _is_ip(host):
        return [host]

    try:
        ips = socket.gethostbyname_ex(host)[2]
        return ips if ips else [host]
    except (socket.gaierror, socket.herror):
        return [host]


def _is_ip(host: str) -> bool:
    """检查是否为 IP 地址"""
    try:
        socket.inet_aton(host)
        return True
    except (socket.error, OSError):
        return False


def ip_range_from_cidr(cidr: str) -> List[str]:
    """将 CIDR 格式转换为 IP 列表"""
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ImportError:
        # Python 3.3+ 内置 ipaddress
        # 降级处理
        base_ip, bits = cidr.split("/")
        bits = int(bits)
        ips = []
        octets = [int(x) for x in base_ip.split(".")]
        if bits >= 24:
            start = 0
            end = 2 ** (32 - bits)
            for i in range(start, end):
                ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{i}"
                ips.append(ip)
        return ips


def ip_range_from_dash(ip_range: str) -> List[str]:
    """将 192.168.1.1-100 格式转换为 IP 列表"""
    base, end = ip_range.rsplit("-", 1)
    octets = base.split(".")
    start_octet = int(octets[-1])
    end_octet = int(end)
    prefix = ".".join(octets[:-1])

    return [f"{prefix}.{i}" for i in range(start_octet, end_octet + 1)]


def is_port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    """检查端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def format_url(ip: str, port: int, ssl: bool = False) -> str:
    """格式化 URL"""
    protocol = "https" if ssl else "http"
    return f"{protocol}://{ip}:{port}"


def extract_sensitive_info(text: str) -> dict:
    """
    从配置文件中提取敏感信息

    支持的字段：
        - admpwd: Web管理密码
        - vtypasswd: Telnet密码
        - model: 设备型号
        - sn: 序列号
        - version: 固件版本
        - dhcp: DHCP配置
        - ntp: NTP配置
    """
    info = {}

    patterns = {
        "admpwd": [
            r'admpwd\s*=\s*"?([^"\s]+)',
            r'admin_password\s*=\s*"?([^"\s]+)',
            r'web_password\s*=\s*"?([^"\s]+)',
        ],
        "vtypasswd": [
            r'vtypasswd\s*=\s*"?([^"\s]+)',
            r'telnet_password\s*=\s*"?([^"\s]+)',
            r'userpass\s*=\s*"?([^"\s]+)',
        ],
        "model": [
            # Miniware 格式: ER8300G2-X/ERHMG2V100D026 (第9行)
            r'(ER\d+[\w-]*)/[\w\d]+',
            # 通用格式
            r'model\s*=\s*"?([^"\s]+)',
            r'device_model\s*=\s*"?([^"\s]+)',
        ],
        "version": [
            # Miniware 格式: ERHMG2V100D026 (型号/版本的第二部分)
            r'ER\d+[\w-]*/([\w\d]+)',
            r'version\s*=\s*"?([^"\s]+)',
            r'software_version\s*=\s*"?([^"\s]+)',
        ],
        "serial": [
            r'serial\s*=\s*"?([^"\s]+)',
            r'sn\s*=\s*"?([^"\s]+)',
        ],
        "name": [
            # Miniware: name=H3C (第15行)
            r'^\s*name\s*=\s*"?([^"\s]+)',
        ],
        "passwd": [
            # Miniware: passwd= (空密码, 第16行)
            r'^\s*passwd\s*=\s*"?([^"\s]*)',
        ],
        "dhcp_server": [
            r'dhcp_server\s*=\s*"?([^"\s]+)',
            r'dhcpserver\s*=\s*"?([^"\s]+)',
        ],
        "ntp_server": [
            r'ntp_server\s*=\s*"?([^"\s]+)',
            r'ntpserver\s*=\s*"?([^"\s]+)',
        ],
        "dns_master": [
            r'dnsmast\s*=\s*"?([^"\s]+)',
        ],
        "dns_slave": [
            r'dnsslav\s*=\s*"?([^"\s]+)',
        ],
        "telnet_enable": [
            r'telnetenable\s*=\s*"?([^"\s]+)',
        ],
        "web_verify": [
            r'webverifycode\s*=\s*"?([^"\s]+)',
        ],
        "admpwdpromt": [
            # Miniware: admpwdpromt=ahly (密码找回提示, 第151行)
            r'admpwdpromt\s*=\s*"?([^"\s]+)',
        ],
        "admapseten": [
            # Miniware: admapseten=1 (是否允许密码找回)
            r'admapseten\s*=\s*"?([^"\s]+)',
        ],
        "admappwdtype": [
            # Miniware: admappwdtype=1 (密码类型)
            r'admappwdtype\s*=\s*"?([^"\s]+)',
        ],
        "vtypasswdtype": [
            # Miniware: vtypasswdtype=simple (密码类型)
            r'vtypasswdtype\s*=\s*"?([^"\s]+)',
        ],
        "vtyauthmode": [
            # Miniware: vtyauthmode=password (认证模式)
            r'vtyauthmode\s*=\s*"?([^"\s]+)',
        ],
    }

    for key, pattern_list in patterns.items():
        for pattern in pattern_list:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip('"')
                break

    return info


def format_result(result: dict) -> str:
    """格式化扫描结果为可读字符串"""
    lines = []
    lines.append(f"目标: {result.get('target', 'N/A')}")
    lines.append(f"状态: {'✓ 脆弱' if result.get('vulnerable') else '✗ 安全'}")
    lines.append(f"类型: {result.get('type', 'N/A')}")

    if result.get("detail"):
        lines.append(f"详情: {result['detail']}")

    if result.get("sensitive_info"):
        lines.append("敏感信息:")
        for key, value in result["sensitive_info"].items():
            lines.append(f"  - {key}: {value}")

    return "\n".join(lines)


def export_to_csv(results: List[dict], filepath: str) -> bool:
    """将结果导出为 CSV 文件"""
    import csv
    import os

    try:
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "目标", "端口", "脆弱", "漏洞类型", "指纹",
                "Web密码", "Telnet密码", "设备型号", "详情"
            ])
            for r in results:
                sensitive = r.get("sensitive_info", {})
                writer.writerow([
                    r.get("target", ""),
                    r.get("port", ""),
                    "是" if r.get("vulnerable") else "否",
                    r.get("type", ""),
                    r.get("fingerprint", ""),
                    sensitive.get("admpwd", ""),
                    sensitive.get("vtypasswd", ""),
                    sensitive.get("model", ""),
                    r.get("detail", ""),
                ])
        return True
    except Exception:
        return False


def export_to_txt(results: List[dict], filepath: str) -> bool:
    """将结果导出为 TXT 文件"""
    import os

    try:
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("H3C 路由器配置泄露检测报告\n")
            f.write("=" * 60 + "\n\n")
            for i, r in enumerate(results, 1):
                f.write(f"结果 #{i}\n")
                f.write("-" * 40 + "\n")
                f.write(format_result(r))
                f.write("\n\n")
        return True
    except Exception:
        return False
