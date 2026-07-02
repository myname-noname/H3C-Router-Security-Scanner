"""
PoC 基类 - 所有漏洞检测模块的基类

重要：路径穿越 payload 必须使用原始 socket 发送，因为 Python requests 库会自动
规范化 URL 路径（如 /userLogin.asp/../actionpolicy_status/../ER8300G2-X.cfg
会被合并为 /ER8300G2-X.cfg），导致路径穿越失效。
"""
import socket
import ssl as ssl_module
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List


class RawHTTPResponse:
    """原始 HTTP 响应模拟"""
    def __init__(self, status_code: int, headers: dict, text: str):
        self.status_code = status_code
        self.headers = headers
        self.text = text

    def __repr__(self):
        return f"<RawHTTPResponse {self.status_code}>"


class PoCBase(ABC):
    """PoC 基类"""

    # 漏洞信息
    NAME = ""
    TYPE = ""
    SEVERITY = "medium"  # critical, high, medium, low, info
    DESCRIPTION = ""
    CVE = ""

    def __init__(self, target: str, port: int, ssl: bool = False, timeout: int = 5):
        self.target = target.strip()
        self.port = port
        self.ssl = ssl
        self.timeout = timeout
        self.base_url = self._build_base_url()

    def _build_base_url(self) -> str:
        """构建基础 URL"""
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.target}:{self.port}"

    def _build_request_headers(self, path: str) -> str:
        """构建原始 HTTP 请求头"""
        host = f"{self.target}:{self.port}"
        headers = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) "
            f"Gecko/20100101 Firefox/140.0\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,"
            f"en-US;q=0.3,en;q=0.2\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Connection: close\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"Priority: u=0, i\r\n"
            f"\r\n"
        )
        return headers

    def get(self, path: str) -> Optional[RawHTTPResponse]:
        """
        使用原始 socket 发送 GET 请求，避免 Python 路径规范化。
        路径穿越 payload 中的 ../ 必须原样发送到服务器。
        """
        try:
            # 创建 socket 连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if self.ssl:
                ctx = ssl_module.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_module.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)

            sock.connect((self.target, self.port))

            # 发送原始 HTTP 请求（不做任何路径规范化）
            raw_request = self._build_request_headers(path)
            sock.sendall(raw_request.encode("utf-8"))

            # 接收响应
            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break

            sock.close()

            # 解析响应
            if not response_data:
                return None

            # 分割 header 和 body
            header_end = response_data.find(b"\r\n\r\n")
            if header_end == -1:
                return None

            raw_headers = response_data[:header_end].decode("utf-8", errors="replace")
            raw_body = response_data[header_end + 4:]

            # 解析状态码
            status_line = raw_headers.split("\r\n")[0]
            status_code = int(status_line.split(" ")[1])

            # 解析 headers
            headers = {}
            for line in raw_headers.split("\r\n")[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            # 解码 body（处理 gzip/deflate）
            content_encoding = headers.get("content-encoding", "")
            body_text = self._decode_body(raw_body, content_encoding)

            return RawHTTPResponse(
                status_code=status_code,
                headers=headers,
                text=body_text,
            )

        except Exception:
            return None

    def _decode_body(self, raw_body: bytes, content_encoding: str) -> str:
        """解码响应体"""
        try:
            if "gzip" in content_encoding:
                import gzip
                try:
                    raw_body = gzip.decompress(raw_body)
                except Exception:
                    pass
            elif "deflate" in content_encoding:
                import zlib
                try:
                    raw_body = zlib.decompress(raw_body)
                except Exception:
                    pass
        except Exception:
            pass

        # 尝试多种编码解码
        for encoding in ["utf-8", "gbk", "gb2312", "latin-1"]:
            try:
                return raw_body.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw_body.decode("utf-8", errors="replace")

    def post(self, path: str, data: str = None) -> Optional[RawHTTPResponse]:
        """发送 POST 请求（使用原始 socket）"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if self.ssl:
                ctx = ssl_module.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_module.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.target)

            sock.connect((self.target, self.port))

            # 构建 POST 请求
            host = f"{self.target}:{self.port}"
            body = data or ""
            req = (
                f"POST {path} HTTP/1.0\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) "
                f"Gecko/20100101 Firefox/140.0\r\n"
                f"Accept: */*\r\n"
                f"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )
            sock.sendall(req.encode("utf-8"))

            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break

            sock.close()

            if not response_data:
                return None

            header_end = response_data.find(b"\r\n\r\n")
            if header_end == -1:
                return None

            raw_headers = response_data[:header_end].decode("utf-8", errors="replace")
            raw_body = response_data[header_end + 4:]

            status_line = raw_headers.split("\r\n")[0]
            status_code = int(status_line.split(" ")[1])

            headers = {}
            for line in raw_headers.split("\r\n")[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            content_encoding = headers.get("content-encoding", "")
            body_text = self._decode_body(raw_body, content_encoding)

            return RawHTTPResponse(
                status_code=status_code,
                headers=headers,
                text=body_text,
            )

        except Exception:
            return None

    @abstractmethod
    def check(self) -> Dict[str, Any]:
        """
        执行漏洞检测

        Returns:
            dict 包含：
                - target: 目标地址
                - port: 端口
                - vulnerable: 是否脆弱
                - type: 漏洞类型
                - detail: 详情
                - sensitive_info: 提取的敏感信息
                - fingerprint: 指纹信息
        """
        pass

    def _build_result(self, vulnerable: bool = False, type_: str = "",
                       detail: str = "", sensitive_info: Optional[Dict] = None,
                       fingerprint: str = "") -> Dict[str, Any]:
        """构建统一的结果格式"""
        return {
            "target": self.target,
            "port": self.port,
            "vulnerable": vulnerable,
            "type": type_ or self.TYPE,
            "detail": detail,
            "sensitive_info": sensitive_info or {},
            "fingerprint": fingerprint,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.target}:{self.port}>"
