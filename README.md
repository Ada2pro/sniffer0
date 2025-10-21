# PyQt5 网络嗅探器

这是一个使用 PyQt5 构建的图形化网络嗅探器示例。界面参考了 Wireshark 的布局，支持实时抓包、协议解析、原始数据查看，提供协议/端口/地址级别的捕获与显示过滤，并通过图表与仪表盘展示统计信息。

## 功能概览
- 选择网卡并开始/停止抓包
- 在表格中实时显示数据包摘要信息
- 展示协议分层解析树和十六进制原始数据
- 支持捕获前的 BPF 过滤器与捕获后的组合显示过滤器（`protocol:tcp port:80 host:example.com` 等）
- 针对 TCP、UDP、ARP、IGMP、ICMP、DNS 等常见协议提供细化解析
- 自动追踪 HTTP/HTTPS、FTP、DNS 等应用层会话，重组 HTTP 请求/响应并展示交互过程
- 自动提取 HTTP 会话中的文件、凭证与 Cookie，支持一键保存可下载文件
- 统计协议分布、访问网站排行、流量分类，并提供仪表盘式流量累计视图
- 提供 TCP/UDP 会话追踪视图，可快速跳转到对应流的完整对话

## 环境要求
- Python 3.9+
- [PyQt5](https://pypi.org/project/PyQt5/)
- [scapy](https://scapy.net/)
- [matplotlib](https://matplotlib.org/)

使用前需要确保具备捕获网络数据包的权限（例如在 Linux 上以 root 身份运行）。

## 快速开始
```bash
python -m venv .venv
source .venv/bin/activate  # Windows 下使用 .venv\\Scripts\\activate
pip install -r requirements.txt  # 如果没有 requirements.txt，请按需安装 PyQt5、scapy、matplotlib
python main.py
```

### 显示过滤器语法

- `protocol:<name>`：协议类型（如 `protocol:tcp`、`protocol:dns`）。
- `src:<ip>` / `dst:<ip>`：源/目的地址匹配，支持部分匹配。
- `port:<number>`：源或目的端口匹配。
- `sport:<number>` / `dport:<number>`：仅匹配源/目的端口。
- `host:<keyword>`：按域名或 SNI 过滤。
- 其他未带冒号的关键词将用于匹配摘要信息列。

多个条件可通过空格组合，条件之间为“与”的关系。

## 使用 PyInstaller 打包为单文件 exe
1. **安装 PyInstaller 以及项目依赖：**
   ```bash
   pip install pyinstaller pyqt5 scapy matplotlib
   ```

2. **准备资源文件（可选）：**
   - 如果应用包含图标或其他外部资源，请将它们放在一个已知路径下，例如 `resources/app.ico`。
   - 在运行打包命令时，通过 `--add-data "resources/app.ico;resources"` 将其一并打包（Windows 下分隔符使用分号）。

3. **执行打包命令：**
   ```bash
   pyinstaller \
       --onefile \
       --noconsole \
       --name sniffer \
       --icon resources/app.ico \  # 如果没有图标可以删除该参数
       --hidden-import scapy.all \
       --hidden-import PyQt5.sip \
       main.py
   ```

   - `--onefile` 生成单个可执行文件。
   - `--noconsole` 隐藏控制台窗口（如果希望保留控制台，可移除）。
   - `--hidden-import` 参数确保 PyInstaller 能正确收集 scapy、PyQt5 等动态导入的模块。
   - 如果应用使用了其他资源或数据文件，可继续追加 `--add-data` 参数。

4. **查看输出：**
   - 成功执行后，可在 `dist/` 目录中找到 `sniffer.exe`。
   - 将该文件以及必须的运行库一起分发即可。

> 提示：如果打包后的程序在运行时缺少依赖，可通过 `pyinstaller --clean ...` 重新打包，或在命令中添加更多 `--hidden-import` 项。

## 许可证
MIT
