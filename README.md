# PyQt5 网络嗅探器

这是一个使用 PyQt5 构建的图形化网络嗅探器示例。界面参考了 Wireshark 的布局，支持实时抓包、协议解析、原始数据查看，以及基于 matplotlib 的协议分布统计图表。

## 功能概览
- 选择网卡并开始/停止抓包
- 在表格中实时显示数据包摘要信息
- 展示协议分层解析树和十六进制原始数据
- 统计不同协议的数据包数量并绘制饼图

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
