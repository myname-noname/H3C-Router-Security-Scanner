"""
日志模块 - 提供统一的日志记录功能
"""
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional


# 日志颜色（支持 Windows）
class ColoredFormatter(logging.Formatter):
    """带颜色的日志格式化器"""
    COLORS = {
        'DEBUG': '\033[36m',     # 青色
        'INFO': '\033[32m',      # 绿色
        'WARNING': '\033[33m',   # 黄色
        'ERROR': '\033[31m',     # 红色
        'CRITICAL': '\033[35m',  # 紫色
    }
    RESET = '\033[0m'

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)


# 全局日志实例
_logger: Optional[logging.Logger] = None


def setup_logger(name: str = "H3C-Scanner", log_file: Optional[str] = None,
                 level: str = "INFO", console: bool = True) -> logging.Logger:
    """
    配置并获取日志记录器

    Args:
        name: 日志记录器名称
        log_file: 日志文件路径，None 则不写文件
        level: 日志级别
        console: 是否输出到控制台
    """
    global _logger

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # 日志格式
    fmt = ColoredFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    file_fmt = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 控制台输出
    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

    # 文件输出
    if log_file:
        os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
        fh = RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
        )
        fh.setFormatter(file_fmt)
        logger.addHandler(fh)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """获取全局日志记录器"""
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger


# 便捷函数
def debug(msg, *args, **kwargs):
    get_logger().debug(msg, *args, **kwargs)

def info(msg, *args, **kwargs):
    get_logger().info(msg, *args, **kwargs)

def warning(msg, *args, **kwargs):
    get_logger().warning(msg, *args, **kwargs)

def error(msg, *args, **kwargs):
    get_logger().error(msg, *args, **kwargs)

def critical(msg, *args, **kwargs):
    get_logger().critical(msg, *args, **kwargs)
