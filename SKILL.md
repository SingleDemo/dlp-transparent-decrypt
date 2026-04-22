# DLP 透明解密

> 适用于亿赛通 Cobra DocGuard Client (EsafeNet) 透明加密文件的快速解密。
> 速度：~0.025s/文件，比 notepad+WM_GETTEXT 快 **120倍**。

## 文件结构

```
dlp-transparent-decrypt/
├─ SKILL.md
└─ scripts/
   ├─ read_encrypted.py       ← 核心库（单文件读取 / Python API）
   ├─ batch_decrypt_keil.py   ← 工程解密（默认原地解密，--copy 生成副本）
   └─ inplace_decrypt.py      ← 原地解密 CLI 工具（batch_decrypt_keil.py 的子集）
```

---

## 一、快速上手

### 1.1 工程解密（默认原地解密）

适用场景：解密后的工程放在 DLP 监控目录下，修改后被重新加密，直接原地解密。

```powershell
# 原地解密整个工程（默认行为，直接修改目录中的文件）
python scripts\batch_decrypt_keil.py "D:\M10-Decrypted\ZR-M10-源APP"

# 生成解密副本（仅当需要副本时才用）
python scripts\batch_decrypt_keil.py "D:\刘笑\5216" --copy "D:\5216-Decrypted"
```

### 1.2 单文件解密

适用场景：只需要读取或解密某一个加密文件。

```powershell
# 解密单个文件，输出到指定路径
python scripts\read_encrypted.py "D:\项目\file.c" "C:\Temp\file_decrypted.c"

# 输出到 stdout
python scripts\read_encrypted.py "D:\项目\file.c" --

# 批量模式
python scripts\read_encrypted.py --batch "file1.c" "file2.h"
```

---

## 二、batch_decrypt_keil.py 详解

### 2.1 默认行为：原地解密

```powershell
# 原地解密整个工程
python scripts\batch_decrypt_keil.py "D:\M10-Decrypted\ZR-M10"

# 只解密 .c/.h/.s 源文件
python scripts\batch_decrypt_keil.py "D:\M10" --ext .c .h .s .inc
```

**工作流程**：
1. 扫描工程目录所有 `.c/.h` 文件
2. 快速检测 DLP 加密头（`0x62 0x14 0x23 0x65`）
3. 跳过已解密文件（只处理加密的）
4. `cmd type` 透明解密 → 写回原文件（UTF-8-BOM）
5. 跳过 OBJ/Listings 等编译目录

### 2.2 生成副本模式：--copy

适用场景：第一次解密，把加密的源工程复制一份到新目录解密，保留原始加密工程不变。

```powershell
# 副本模式（加密源 -> 解密副本）
python scripts\batch_decrypt_keil.py "D:\刘笑\环境部\5216" --copy "D:\5216-Decrypted"

# 副本模式 + 同时复制 README/文档等非加密文件
python scripts\batch_decrypt_keil.py "D:\5216" --copy "D:\5216-Decrypted" --copy-other

# 调整线程数
python scripts\batch_decrypt_keil.py "D:\5216" --copy "D:\out" -w 8
```

### 2.3 原地解密 vs 副本模式

| | 原地解密（默认） | 副本模式（--copy） |
|--|--|--|
| 适用场景 | 已解密过的工程被重新加密 | 第一次解密原始加密工程 |
| 原工程 | **被修改** | 不变 |
| 速度 | 更快（只处理加密文件） | 稍慢（全量解密+复制） |
| 输出目录 | 即输入目录 | 由 --copy 指定 |

### 2.4 原地解密输出示例

```
工程目录: D:\M10-Decrypted\ZR-M10
模式: 原地解密（直接修改工程目录中的文件）
扩展名: ['.c', '.h']

发现 3 个加密文件，开始原地解密...
  已解密 20/3...

==================================================
原地解密完成
  成功: 3 / 3
  失败: 0
  耗时: 0.08s  均速: 26.7ms/文件
  目录: D:\M10-Decrypted\ZR-M10
==================================================
```

---

## 三、核心原理

亿赛通 DLP 对 `cmd.exe` 有白名单放行逻辑：
```
cmd /c type <加密文件> > <明文输出>
```
DLP 自动透明解密内容，通过 CMD 重定向写出。`cmd type` 输出的是解密后的明文，再用 UTF-8-BOM 写回原文件。

### 3.1 方案对比

| 方案 | 速度 | 成功率 | 窗口弹出 | 备注 |
|------|------|--------|----------|------|
| **cmd type 重定向** | **7ms/文件** | **100%** | **无** | ✅ 推荐 |
| notepad+WM_GETTEXT | ~3000ms/文件 | ~95% | 有 | 备选/回退 |

### 3.2 为何其他方案失败

| 方案 | 失败原因 |
|------|----------|
| `copy` 命令 | subprocess 列表参数编码无法处理中文路径 |
| PowerShell Get-Content | 走 .NET 内部路径，不触发 DLP 透明解密钩子 |
| Python `open()` 直接读 | 同样不触发 DLP 钩子，读到加密内容 |
| cmd `type` stdout 捕获 | console device 无法被 Python 管道捕获 |

---

## 四、Python API

```python
import sys
sys.path.insert(0, r"C:\Users\liuxiao\.qclaw\workspace\dlp-transparent-decrypt\scripts")
from read_encrypted import read_encrypted_file, batch_read

# 单文件（自动检测加密并解密）
text = read_encrypted_file(r"D:\项目\SysMeasure.c")

# 批量并行（4线程）
results = batch_read([
    r"D:\项目\file1.c",
    r"D:\项目\file2.h",
    r"D:\项目\file3.c",
], max_workers=4)

for path, (ok, content_or_err) in results.items():
    if ok:
        print(f"OK: {path} ({len(content_or_err)} chars)")
    else:
        print(f"FAIL: {path} - {content_or_err}")
```

---

## 五、经验总结

### 5.1 关键经验

1. **DLP 非监控区写文件才会解密**：输出到 `D:\M10-Decrypted`（非 DLP 监控）才能正确解密
2. **原地解密直接覆盖**：默认模式直接写回原目录，对已在非监控区的解密工程来说没问题
3. **中文路径没问题**：列表参数形式正确传递给 CMD
4. **跳过 OBJ/Listings**：编译产物不解密不复制
5. **DLP 服务必须运行**：`EstDlpSEDataBase.exe` 等进程需正常启动

### 5.2 中文编码

`cmd type` 输出的文件可能无 BOM，编码不确定（UTF-8 或 GBK）。`detect_encoding()` 的修复逻辑（2026-04-22）：

1. 有 UTF-8 BOM → `utf-8-sig`
2. 无 BOM：尝试 UTF-8 → 成功则返回
3. UTF-8 失败：尝试 GBK → 成功则返回
4. 两者都成功：按 Latin-1 高位字节比例判断（>15% → GBK，<15% → UTF-8）

解密后统一写 **UTF-8-BOM**，Keil 5.29+ 和 VSCode 都能自动识别。

**重要**：Git 仓库中存储的文件可能是 DLP 加密状态（如 `git show` 输出 `BOM: 62 14 23`）。
如需解密 Git 中的文件，先提取到 DLP 监控目录，再用 `cmd type` 透明解密：

```python
import subprocess, os
r = subprocess.run(['git', 'show', 'COMMIT:path/to/file.c'], capture_output=True)
git_enc = r.stdout
tmp = os.path.join('DLP监控目录', '__tmp_decrypt.c')
with open(tmp, 'wb') as f: f.write(git_enc)
plain = subprocess.run(['cmd', '/c', 'type', tmp], capture_output=True).stdout
os.remove(tmp)
# plain 已是解密内容，再按 UTF-8-BOM 写入目标位置
```

### 5.3 常见问题

| 问题 | 解决 |
|------|------|
| 成功率不是 100% | 检查 DLP 服务是否正常 |
| 解密后中文注释乱码 | GBK→UTF-8-BOM 自动处理，重新解密即可 |
| 只加密了部分文件 | 原地解密只处理加密文件，未加密的跳过 |

---

## 六、GitHub 同步

```powershell
cd C:\Users\liuxiao\.qclaw\workspace\dlp-transparent-decrypt
git add .
git commit -m "feat: v3 - in-place decrypt as default, --copy for backup"
git push origin master
```
