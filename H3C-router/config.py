"""
配置模块 - 加载设备指纹规则和程序配置
"""
import csv
import json
import os
from typing import List, Dict, Optional, Any


# 默认配置
DEFAULT_CONFIG = {
    "timeout": 5,            # HTTP 请求超时
    "threads": 10,           # 默认线程数
    "max_threads": 50,       # 最大线程数
    "ports": [8081, 10001, 8090],  # 默认扫描端口
    "output_dir": "results", # 结果输出目录
    "log_level": "INFO",     # 日志级别
}

# 全局配置字典
CONFIG = DEFAULT_CONFIG.copy()


def load_config(config_path: Optional[str] = None) -> Dict:
    """加载配置，后续可扩展从文件加载"""
    global CONFIG
    if config_path and os.path.exists(config_path):
        pass  # 预留扩展：从 JSON/YAML 加载自定义配置
    return CONFIG


def update_config(**kwargs) -> None:
    """更新配置项"""
    global CONFIG
    CONFIG.update(kwargs)


def get_config(key: str, default=None):
    """获取配置项"""
    return CONFIG.get(key, default)


class Rule:
    """H3C 设备指纹规则"""
    def __init__(self, oid: str, vendor: str, model: str, version: str, fingerprint: str):
        self.oid = oid
        self.vendor = vendor
        self.model = model
        self.version = version
        self.fingerprint = fingerprint

    def __repr__(self):
        return f"<Rule {self.vendor} {self.model}>"

    def to_dict(self) -> Dict:
        return {
            "oid": self.oid,
            "vendor": self.vendor,
            "model": self.model,
            "version": self.version,
            "fingerprint": self.fingerprint,
        }


def load_rules(csv_path: str = "rules.csv") -> List[Rule]:
    """从 CSV 加载 H3C 设备指纹规则"""
    rules = []
    if not os.path.exists(csv_path):
        return _default_rules()

    try:
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rules.append(Rule(
                    oid=row.get("oid", ""),
                    vendor=row.get("vendor", "H3C"),
                    model=row.get("model", ""),
                    version=row.get("version", ""),
                    fingerprint=row.get("fingerprint", ""),
                ))
    except Exception:
        rules = _default_rules()

    return rules if rules else _default_rules()


def _default_rules() -> List[Rule]:
    """默认 H3C 设备规则"""
    return [
        Rule("1.3.6.1.4.1.25506.1.1", "H3C", "ER8300G2-X", "Unknown", "H3C"),
        Rule("1.3.6.1.4.1.25506.1.2", "H3C", "ER5200G2", "Unknown", "H3C"),
        Rule("1.3.6.1.4.1.25506.1.3", "H3C", "ER3200G2", "Unknown", "H3C"),
        Rule("1.3.6.1.4.1.25506.1.4", "H3C", "ER3100G2", "Unknown", "H3C"),
        Rule("1.3.6.1.4.1.25506.1.5", "H3C", "ER6300G2", "Unknown", "H3C"),
    ]


def load_fingerprints(finger_json_path: str = "finger.json") -> List[Dict[str, Any]]:
    """
    从 finger.json 加载设备指纹规则
    返回 H3C 相关的指纹规则列表
    """
    if not os.path.exists(finger_json_path):
        return []

    try:
        with open(finger_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

    h3c_fingerprints = []

    # finger.json 可能是数组或对象
    if isinstance(data, list):
        for item in data:
            if _is_h3c_related(item):
                h3c_fingerprints.append(item)
    elif isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if _is_h3c_related(item):
                        h3c_fingerprints.append(item)

    return h3c_fingerprints


def _is_h3c_related(item: Any) -> bool:
    """判断指纹项是否与 H3C 相关"""
    if not isinstance(item, dict):
        return False

    cms = str(item.get("cms", "")).lower()
    vendor = str(item.get("vendor", "")).lower()
    keyword = str(item.get("keyword", "")).lower()

    h3c_keywords = ["h3c", "hp", "comware", "3com", "hpe"]

    return any(k in cms or k in vendor or k in keyword for k in h3c_keywords)
