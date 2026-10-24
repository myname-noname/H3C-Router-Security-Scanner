"""
PoC 自动发现模块
自动扫描 pocs 目录下的所有 PoC 类
"""
import importlib
import inspect
import os
import pkgutil
from typing import Dict, List, Type, Any

from pocs.base import PoCBase


# 缓存已发现的 PoC
_discovered_pocs: Dict[str, Type[PoCBase]] = {}


def discover_pocs() -> Dict[str, Type[PoCBase]]:
    """
    自动发现所有 PoC 类

    扫描 pocs 目录下所有 .py 文件（排除 __init__.py 和 base.py），
    自动注册继承自 PoCBase 的类。

    Returns:
        dict: {类名: PoC类}
    """
    global _discovered_pocs

    if _discovered_pocs:
        return _discovered_pocs

    pocs_dir = os.path.dirname(__file__)

    for importer, modname, ispkg in pkgutil.iter_modules([pocs_dir]):
        # 跳过 __init__ 和 base 模块
        if modname in ("__init__", "base"):
            continue

        try:
            module = importlib.import_module(f"pocs.{modname}")
        except ImportError:
            continue

        # 查找模块中所有继承自 PoCBase 的类
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj)
                    and issubclass(obj, PoCBase)
                    and obj is not PoCBase):
                _discovered_pocs[name] = obj

    return _discovered_pocs


def get_poc(name: str) -> Type[PoCBase]:
    """根据名称获取 PoC 类"""
    pocs = discover_pocs()
    return pocs.get(name)


def get_all_poc_names() -> List[str]:
    """获取所有 PoC 名称列表"""
    return list(discover_pocs().keys())


def get_all_poc_info() -> List[Dict[str, Any]]:
    """获取所有 PoC 的摘要信息"""
    info_list = []
    for name, poc_class in discover_pocs().items():
        info_list.append({
            "name": name,
            "display_name": getattr(poc_class, "NAME", name),
            "type": getattr(poc_class, "TYPE", ""),
            "severity": getattr(poc_class, "SEVERITY", "info"),
            "description": getattr(poc_class, "DESCRIPTION", ""),
            "cve": getattr(poc_class, "CVE", ""),
        })
    return info_list


def create_poc_instance(name: str, target: str, port: int,
                         ssl: bool = False, timeout: int = 5) -> PoCBase:
    """
    创建 PoC 实例

    Args:
        name: PoC 类名
        target: 目标 IP/域名
        port: 端口
        ssl: 是否使用 HTTPS
        timeout: 超时时间

    Returns:
        PoC 实例
    """
    poc_class = get_poc(name)
    if poc_class is None:
        raise ValueError(f"未找到 PoC: {name}")
    return poc_class(target=target, port=port, ssl=ssl, timeout=timeout)
