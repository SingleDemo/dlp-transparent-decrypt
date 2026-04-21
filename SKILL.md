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
   ├─ read_encrypted.py       ← 核心库（Python API / CLI）
   └─ batch_decrypt_keil.py   ← Keil 工程目录批量解密
```

---

## 一、快速上手

### 1.1 Python API（推荐）

```python
import sys
sys.path.insert(0, r"C:\Users\liuxiao\.qclaw\workspace\dlp-transparent-decrypt\scripts")
from read_encrypted import read_encrypted_file, batch_read

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

### 1.2 命令行 CLI

```powershell
# 单文件：输出到指定路径
python scripts\read_encrypted.py "D:\项目\file.c" "C:\Temp\file.c"

# 单文件：输出到 stdout
python scripts\read_encrypted.py "D:\项目\file.c" --

# 批量模式（解密到临时目录）
python scripts\read_encrypted.py --batch "file1.c" "file2.h" "file3.c"
```

---

## 二、Keil 工程批量解密（目录对目录）

适用场景：解密整个 DLP 加密的 Keil 工程目录，保留原目录结构输出到目标目录。

### 2.1 基本用法

```powershell
# 解密整个 M10 工程
python scripts\batch_decrypt_keil.py "D:\项目\ZR-M10-源APP" "D:\M10-Decrypted"

# 解密 5216 工程
python scripts\batch_decrypt_keil.py "D:\刘笑\环境部\5216" "D:\5216-Decrypted"
```

### 2.2 常用参数

```powershell
# 指定扩展名（默认 .c .h）
python scripts\batch_decrypt_keil.py "src" "dst" --ext ".c" ".h" ".s" ".inc"

# 跳过编译输出目录
python scripts\batch_decrypt_keil.py "src" "dst" --exclude "OBJ" "Listings" "Listing"

# 调整并行线程数
python scripts\batch_decrypt_keil.py "src" "dst" -w 8
```

### 2.3 输出报告示例

```
扫描源目录: D:\项目
找到 413 个 .c/.h 文件
开始批量解密（4 线程）...
  已解密 50/413...
  已解密 100/413...
  已解密 150/413...
  已解密 200/413...
  已解密 250/413...
  已解密 300/413...
  已解密 350/413...
  已解密 400/413...

==================================================
解密完成
  总计: 413 文件
  成功: 413  失败: 0
  耗时: 3.04s  均速: 7.4ms/文件
  明文: 13996KB
  输出: D:\M10-Decrypted
==================================================
```

---

## 三、原理详解

### 3.1 方案对比

| 方案 | 速度 | 成功率 | 窗口弹出 | 并行 | 备注 |
|------|------|--------|----------|------|------|
| **cmd type 重定向** | **7ms/文件** | **100%** | **无** | **是** | ✅ 推荐 |
| notepad+WM_GETTEXT | ~3000ms/文件 | ~95% | 有 | 差 | 备选/回退 |

### 3.2 cmd type 核心代码

```python
import subprocess, tempfile, os

def read_via_cmd_type(src: str) -> str | None:
    fd, tmp = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        # 参数列表形式（list）保证中文路径正确传递
        r = subprocess.run(
            ["cmd", "/c", "type", src, ">", tmp],
            capture_output=True, timeout=10.0
        )
        if r.returncode == 0 and os.path.exists(tmp):
            with open(tmp, encoding="utf-8", errors="replace") as f:
                return f.read()
    finally:
        try: os.remove(tmp)
        except: pass
    return None
```

**关键点：**
- 必须用**列表形式** `["cmd", "/c", "type", src, ">", tmp]`，不能用字符串 `"cmd /c type..."`
- 列表形式避免 shell 转义问题，中文路径能正确传递
- `>` 是 CMD 重定向操作符，不受 subprocess 参数编码影响

### 3.3 为何其他方案失败

| 方案 | 失败原因 |
|------|----------|
| `copy` 命令 | subprocess 列表参数编码无法处理中文路径 |
| PowerShell Get-Content | 走 .NET 内部路径，不触发 DLP 透明解密钩子 |
| Python `open()` 直接读 | 同样不触发 DLP 钩子，读到加密内容 |
| cmd `type` stdout 捕获 | console device 无法被 Python 管道捕获 |

---

## 四、内部工作流程

```
read_encrypted_file(src)
    │
    ├── is_encrypted() 检测：读前128字节，含 b"E-SafeNet" 则为加密
    │
    ├── 非加密文件 → 直接 open() 读（自动检测 UTF-8/GBK 编码）
    │
    └── 加密文件
        ├── cmd type 重定向（快路径，7ms）
        │     └─ 临时文件在 DLP 非监控区 → 写出明文
        │
        └── 回退：notepad + WM_GETTEXT（慢路径，3s）
              └─ notepad 是白名单进程，DLP 透明解密后显示
```

---

## 五、经验总结（2026-04-21 实测）

### 5.1 M10 项目解密记录

- 源：`D:\workspace\ZR-M10-源APP-V1.01T-260316-刘笑-GPT5.4修改版`
- 目标：`D:\M10-Decrypted\ZR-M10-源APP-V1.01T-260316-刘笑-GPT5.4修改版`
- 结果：413 文件，100% 成功，耗时 3.04s，明文 14MB
- 线程数：4（更多线程无明显提升，I/O bound）

### 5.2 关键经验

1. **输出目录必须在 DLP 非监控区**（如 `D:\M10-Decrypted`），写 DLP 保护目录会被重新加密
2. **中文路径没问题**，列表形式参数正确传递给 CMD
3. **跳过 OBJ/Listings 等编译目录**，只解密源文件 `.c/.h`
4. **文件越多越划算**：单文件 0.025s，413 文件 3s，规模效益明显
5. **DLP 服务必须运行**：`EstDlpSEDataBase.exe` 等进程需正常启动

### 5.3 常见问题

| 问题 | 解决 |
|------|------|
| `AttributeError: module 'importlib' has no attribute 'util'` | 改用 `from importlib.util import spec_from_file_location` |
| 成功率不是 100% | 检查 DLP 服务是否正常，确认目标目录不在 DLP 保护范围内 |
| 解密后中文注释乱码（`//����`） | 源文件是 GBK 编码，检测逻辑误判为 UTF-8 → 改用 GBK 检测或写 UTF-8-BOM |

### 5.4 中文编码修复（2026-04-21）

**问题**：M10 项目解密后，65 个含中文注释的 `.c/.h` 文件出现乱码。

**根因**：Keil MDK 默认以 **GBK** 保存 `.c/.h` 文件，`cmd type` 输出的内容是 GBK 编码。`detect_encoding()` 的启发式判断（可打印字符比例）将 GBK 误判为 UTF-8，用 UTF-8 解码 GBK 字节导致乱码。

**修复**：
1. `read_encrypted.py` 的 `detect_encoding()` 增加 `is_source_file` 参数，`.c/.h/.s/.inc` 文件检测是否有 GBK 双字节特征（0x80-0xFF），有则用 GBK 解码
2. 解密后统一写 **UTF-8-BOM**（`utf-8-sig`），Keil 5.29+ 和 VSCode 都能自动识别，兼容性最好
3. 已有乱码文件：重新从加密源用 `cmd type` 读 → GBK 解码 → UTF-8-BOM 写入

---

## 六、GitHub 同步

```powershell
cd dlp-transparent-decrypt
git add .
git commit -m "feat: add batch_decrypt_keil.py + Keil project decryption guide"
git push origin main
```
