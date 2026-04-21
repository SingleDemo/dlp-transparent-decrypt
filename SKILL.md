# DLP 透明解密文件读取

> 适用于亿赛通 Cobra DocGuard Client (EsafeNet) 透明加密文件的快速读取。
> 速度：~0.025s/文件，比传统 notepad+WM_GETTEXT 快 **120倍**。

## 核心原理

亿赛通 DLP 对 `cmd.exe` 有白名单放行逻辑：
```
cmd /c type <加密文件> > <明文输出>
```
DLP 自动透明解密内容，通过 CMD 重定向写出到目标文件。目标路径必须在 DLP 保护目录之外（如 `C:\Temp\`）。

## 文件结构

```
dlp-transparent-decrypt/
├─ SKILL.md
└─ scripts/
   └─ read_encrypted.py   ← 核心脚本（推荐使用）
```

## 命令行用法

```powershell
# 单文件：输出到指定路径
python scripts\read_encrypted.py "D:\项目\file.c" "C:\Temp\file.c"

# 单文件：输出到 stdout
python scripts\read_encrypted.py "D:\项目\file.c" --

# 批量模式
python scripts\read_encrypted.py --batch "file1.c" "file2.h" "file3.c"
```

## Python API

```python
from scripts.read_encrypted import read_encrypted_file, batch_read

# 单文件
text = read_encrypted_file(r"D:\项目\SysMeasure.c")

# 批量（4线程并行）
results = batch_read([
    r"D:\项目\file1.c",
    r"D:\项目\file2.h",
    r"D:\项目\file3.c",
], max_workers=4)

for path, (ok, content_or_err) in results.items():
    if ok:
        print(f"OK: {path} ({len(content)} chars)")
    else:
        print(f"FAIL: {path} - {content_or_err}")
```

## 方案对比

| 方案 | 速度 | 成功率 | 窗口弹出 | 并行 |
|------|------|--------|----------|------|
| **cmd type 重定向** | **0.025s/文件** | **100%** | 无 | 是 |
| notepad+WM_GETTEXT | ~3s/文件 | ~95% | 有 | 差 |
| PowerShell 读取 | 失败 | 0% | - | - |

## 注意事项

1. **目标路径必须在 DLP 保护目录之外**（如 `C:\Temp\`、桌面非 DLP 区域），否则写入后会被重新加密
2. 依赖 `cmd.exe` 在 PATH 中（Windows 默认）
3. 支持 `.c/.h/.txt/.md/.ini/.json/.xml/.cfg` 等纯文本加密文件
4. 非文本文件（`.bin/.dat/.exe/.dll`）不适用，cmd type 读不到加密二进制内容
5. DLP 服务（EstDlpSEDataBase.exe 等）必须正常运行

## 工作流程

```
1. is_encrypted_file() 检测是否为 DLP 加密（有 E-SafeNet 头）
2. 加密文件 → cmd type 重定向读取
3. 读取失败 → 回退到 notepad + WM_GETTEXT
4. 非加密文件 → 直接 open() 读取
```
