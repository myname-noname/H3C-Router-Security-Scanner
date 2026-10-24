"""
核心扫描引擎 - 多线程并发扫描
"""
import os
import time
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

from config import get_config, load_fingerprints
from pocs import discover_pocs, create_poc_instance, get_all_poc_info
from utils.common import (
    parse_target, export_to_csv, export_to_txt, format_result
)
from utils.log import get_logger, setup_logger

logger = get_logger()


class ScanEngine:
    """多线程并发扫描引擎"""

    def __init__(self):
        self._stop_flag = threading.Event()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._results: List[Dict[str, Any]] = []
        self._results_lock = threading.Lock()
        self._progress_callback: Optional[Callable] = None
        self._result_callback: Optional[Callable] = None
        self._log_callback: Optional[Callable] = None
        self._total_tasks = 0
        self._completed_tasks = 0

        # 发现 PoC
        self._poc_infos = get_all_poc_info()
        self._poc_names = list(discover_pocs().keys())

        # 结果输出目录
        self._output_dir = get_config("output_dir", "results")

    @property
    def poc_infos(self) -> List[Dict[str, Any]]:
        """获取所有 PoC 信息"""
        return self._poc_infos

    @property
    def poc_names(self) -> List[str]:
        """获取所有 PoC 名称"""
        return self._poc_names

    @property
    def results(self) -> List[Dict[str, Any]]:
        """获取扫描结果"""
        return self._results

    def set_progress_callback(self, callback: Callable[[int, int], None]):
        """设置进度回调"""
        self._progress_callback = callback

    def set_result_callback(self, callback: Callable[[Dict], None]):
        """设置结果回调（每次发现新结果时调用）"""
        self._result_callback = callback

    def set_log_callback(self, callback: Callable[[str], None]):
        """设置日志回调（每次扫描任务时调用）"""
        self._log_callback = callback

    def start_scan(self, target_input: str, ports: List[int] = None,
                   threads: int = 10, timeout: int = 5,
                   poc_names: List[str] = None):
        """
        启动扫描

        Args:
            target_input: 目标输入（IP、域名、CIDR等）
            ports: 端口列表
            threads: 并发线程数
            timeout: 超时时间
            poc_names: 要使用的 PoC 名称列表，None 表示使用所有
        """
        self._stop_flag.clear()
        self._results.clear()
        self._completed_tasks = 0

        # 解析目标（返回 (ip, port, explicit_port)）
        parsed = parse_target(target_input)
        targets = []
        seen = set()

        for ip, port, explicit in parsed:
            if explicit:
                key = (ip, port)
                if key not in seen:
                    seen.add(key)
                    targets.append((ip, port))
            elif ports:
                for p in ports:
                    key = (ip, p)
                    if key not in seen:
                        seen.add(key)
                        targets.append((ip, p))
            else:
                key = (ip, port)
                if key not in seen:
                    seen.add(key)
                    targets.append((ip, port))

        if not targets:
            logger.error("未解析到有效目标")
            return

        # 确定使用的 PoC
        pocs_to_use = poc_names if poc_names else self._poc_names
        if not pocs_to_use:
            logger.error("未发现可用的 PoC")
            return

        # 计算总任务数
        self._total_tasks = len(targets) * len(pocs_to_use)
        logger.info(f"扫描开始: {len(targets)} 个目标, {len(pocs_to_use)} 个 PoC, "
                    f"共 {self._total_tasks} 个任务, "
                    f"线程数: {threads}")

        # 创建任务列表
        tasks = []
        for ip, port in targets:
            for poc_name in pocs_to_use:
                tasks.append((ip, port, poc_name))

        # 并发执行
        self._executor = ThreadPoolExecutor(max_workers=threads)
        futures = {
            self._executor.submit(self._run_poc, ip, port, poc_name, timeout):
                (ip, port, poc_name)
            for ip, port, poc_name in tasks
        }

        # 收集结果
        for future in as_completed(futures):
            if self._stop_flag.is_set():
                break
            try:
                result = future.result()
                if result:
                    with self._results_lock:
                        self._results.append(result)
                    if self._result_callback:
                        self._result_callback(result)
            except Exception as e:
                logger.error(f"任务执行异常: {e}")
            finally:
                self._completed_tasks += 1
                if self._progress_callback:
                    self._progress_callback(self._completed_tasks, self._total_tasks)

        # 清理
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None

        # 汇总结果
        vuln_count = sum(1 for r in self._results if r.get("vulnerable"))
        logger.info(f"扫描完成: 共 {self._completed_tasks}/{self._total_tasks} 任务, "
                    f"发现 {vuln_count} 个漏洞")

    def stop_scan(self):
        """停止扫描"""
        self._stop_flag.set()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        logger.info("扫描已停止")

    def _run_poc(self, ip: str, port: int, poc_name: str,
                  timeout: int) -> Optional[Dict[str, Any]]:
        """运行单个 PoC"""
        if self._stop_flag.is_set():
            return None

        # 发送扫描进度日志
        if self._log_callback:
            self._log_callback(f"正在扫描 {ip}:{port} - {poc_name}")

        try:
            # 创建 PoC 实例
            ssl = (port == 443)
            poc = create_poc_instance(poc_name, ip, port,
                                       ssl=ssl, timeout=timeout)
            # 执行检测
            result = poc.check()
            return result
        except Exception as e:
            logger.debug(f"{ip}:{port} {poc_name} 检测异常: {e}")
            return None

    def export_results(self, format_type: str = "csv") -> Optional[str]:
        """
        导出扫描结果

        Args:
            format_type: 导出格式 (csv/txt)

        Returns:
            导出文件路径，失败返回 None
        """
        if not self._results:
            logger.warning("没有结果可导出")
            return None

        os.makedirs(self._output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vuln_count = sum(1 for r in self._results if r.get("vulnerable"))

        if format_type == "csv":
            filename = os.path.join(self._output_dir,
                                    f"scan_result_{timestamp}.csv")
            if export_to_csv(self._results, filename):
                logger.info(f"结果已导出到: {filename}")
                return filename
        elif format_type == "txt":
            filename = os.path.join(self._output_dir,
                                    f"scan_report_{timestamp}.txt")
            if export_to_txt(self._results, filename):
                logger.info(f"报告已导出到: {filename}")
                return filename

        logger.error(f"导出失败: {format_type}")
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """获取扫描统计信息"""
        total = len(self._results)
        vuln_count = sum(1 for r in self._results if r.get("vulnerable"))
        safe_count = total - vuln_count

        # 按漏洞类型统计
        type_stats = {}
        for r in self._results:
            if r.get("vulnerable"):
                r_type = r.get("type", "未知")
                type_stats[r_type] = type_stats.get(r_type, 0) + 1

        # 收集敏感信息
        sensitive_info_count = sum(
            1 for r in self._results
            if r.get("sensitive_info")
        )

        return {
            "total": total,
            "vulnerable": vuln_count,
            "safe": safe_count,
            "by_type": type_stats,
            "sensitive_found": sensitive_info_count,
        }


class FingerprintScanner:
    """指纹识别扫描器"""

    def __init__(self):
        self.fingerprints = load_fingerprints()

    def scan(self, target_data: dict) -> dict:
        """
        对目标进行指纹识别

        Args:
            target_data: 目标数据 (包含 url, headers, body 等)

        Returns:
            识别的指纹信息
        """
        result = {
            "cms": "",
            "confidence": 0,
            "method": "",
        }

        for fp in self.fingerprints:
            cms = fp.get("cms", "")
            method = fp.get("method", "")
            location = fp.get("location", "body")
            keywords = fp.get("keyword", [])
            if not isinstance(keywords, list):
                keywords = [keywords]

            # 根据检测位置匹配
            if location == "body":
                content = target_data.get("body", "")
            elif location == "header":
                content = str(target_data.get("headers", ""))
            else:
                content = str(target_data.get("url", ""))

            # 关键词匹配
            for keyword in keywords:
                if keyword and keyword.lower() in content.lower():
                    result["cms"] = cms
                    result["method"] = method
                    result["confidence"] = 100
                    return result

        return result
