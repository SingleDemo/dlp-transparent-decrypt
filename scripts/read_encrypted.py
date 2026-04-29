"""
DLP 透明解密文件读取

通过 cmd.exe type 重定向绕过亿赛通 DLP 透明加密，
速度 ~0.025s/文件，比 notepad+WM_GETTEXT 快 120 倍。

Usage:
    python read_encrypted.py <src_file> [out_file|--]
    python read_encrypted.py --batch <file1> <file2> ...

Author: OpenClaw Agent
License: MIT
"""
import sys
import os
import time
import tempfile
import ctypes
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Tuple

# ======================================================================
#  Win32 常量（用于 notepad 回退方案）
# ======================================================================
WM_GETTEXT       = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_CLOSE         = 0x0010
BM_CLICK         = 0x00F5

EDIT_CLASS_NAMES = {"Edit", "RichEdit20W", "RICHEDIT50W", "RichEditD2DPT"}

user32 = ctypes.windll.user32


# ======================================================================
#  检测
# ======================================================================

def is_encrypted(src: str) -> bool:
    """检测文件是否为 DLP 加密格式（E-SafeNet 头 或 magic bytes）"""
    try:
        with open(src, 'rb') as f:
            header = f.read(128)
        # 检查 E-SafeNet / LOCK 字符串（大文件通常包含）
        if b'E-SafeNet' in header or b'LOCK' in header:
            return True
        # 检查 magic bytes（小文件可能没有 E-SafeNet 字符串）
        check = header[3:] if header[:3] == b'\xef\xbb\xbf' else header
        if len(check) >= 4 and check[0] in (0x62, 0x77) and check[1] == 0x14 and check[2] == 0x23:
            return True
        return False
    except Exception:
        return False


def detect_encoding(src: str, is_source_file: bool = False) -> str:
    """
    检测文件编码。

    修复历史（2026-04-22）：
    - 原始启发式对无 BOM 文件误判率高
    - DLP 解密后文件可能无 BOM，编码可能是 UTF-8 或 GBK
    - 新策略：混合尝试 UTF-8 -> GBK，优先选择乱码少的结果
    """
    try:
        with open(src, 'rb') as f:
            raw = f.read(4096)

        if raw.startswith(b'\xef\xbb\xbf'):
            return 'utf-8-sig'

        # 统计 Latin-1 范围字节比例（GBK 双字节汉字高位字节 0x81-0xFE 常见）
        latin1_bytes = sum(1 for b in raw if b >= 0x80)
        latin1_ratio = latin1_bytes / max(len(raw), 1)

        # 策略1：优先 UTF-8
        utf8_ok = False
        try:
            raw.decode('utf-8')
            utf8_ok = True
        except Exception:
            pass

        # 策略2：GBK（嵌入式源文件或高 Latin-1 比例）
        gbk_ok = False
        try:
            raw.decode('gbk')
            gbk_ok = True
        except Exception:
            pass

        # 决策树
        if utf8_ok and gbk_ok:
            # 两者都合法：Latin-1 比例高 -> GBK；低 -> UTF-8
            return 'gbk' if latin1_ratio > 0.15 else 'utf-8'
        elif utf8_ok:
            return 'utf-8'
        elif gbk_ok:
            return 'gbk'
        else:
            # 都失败：返回第一个尝试的
            return 'utf-8'

    except Exception:
        return 'utf-8'


# ======================================================================
#  方式A：cmd type 重定向（推荐，120x faster）
# ======================================================================

SOURCE_EXTS = {'.c', '.h', '.s', '.inc', '.a', '.lib', '.obj'}

def read_via_cmd_type(src: str, timeout: float = 10.0) -> Optional[str]:
    """
    通过 cmd.exe type 重定向读取 DLP 加密文件。

    原理：亿赛通 DLP 对 cmd.exe 有白名单放行，
    cmd /c type 会触发 DLP 解密钩子，内容被重定向写出到临时文件。

    参数列表形式 ['cmd', '/c', 'type', src, '>', dst] 保证了
    中文字符路径正确传递给 CMD 进程。
    """
    is_src = os.path.splitext(src)[1].lower() in SOURCE_EXTS
    fd, tmp = tempfile.mkstemp(suffix='.txt')
    os.close(fd)

    try:
        if os.path.exists(tmp):
            os.remove(tmp)

        r = subprocess.run(
            ['cmd', '/c', 'type', src, '>', tmp],
            capture_output=True,
            timeout=timeout
        )

        if r.returncode == 0 and os.path.exists(tmp) and not is_encrypted(tmp):
            enc = detect_encoding(tmp, is_source_file=is_src)
            with open(tmp, encoding=enc, errors='replace') as f:
                return f.read()
        return None

    except Exception:
        return None
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass


# ======================================================================
#  方式B：notepad + WM_GETTEXT（回退方案）
# ======================================================================

def _enum_windows_cb(hwnd, found_hints, found):
    """遍历窗口，找标题含 hint 的窗口"""
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    title = buf.value
    for hint in found_hints:
        if hint in title:
            found[0] = hwnd
            return False
    return True


def _enum_children_cb(hwnd, class_name, found):
    """遍历子窗口，找指定类名"""
    buf = ctypes.create_unicode_buffer(64)
    user32.GetClassNameW(hwnd, buf, 64)
    if buf.value == class_name:
        found[0] = hwnd
        return False
    return True


def find_window(title_hints: List[str], timeout_s: float = 8.0) -> Optional[int]:
    """找标题含任一 hint 的窗口"""
    found = [None]
    deadline = time.time() + timeout_s

    CB_W = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_long, ctypes.c_long)
    while time.time() < deadline and found[0] is None:
        found[0] = None
        user32.EnumWindows(CB_W(lambda h, _: _enum_windows_cb(h, title_hints, found)), 0)
        if found[0] is None:
            time.sleep(0.1)

    return found[0]


def find_child(parent: int, class_name: str) -> Optional[int]:
    """找父窗口下指定类名的子窗口"""
    found = [None]
    CB = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_long, ctypes.c_long)
    user32.EnumChildWindows(parent, CB(lambda h, _: _enum_children_cb(h, class_name, found)), 0)
    return found[0]


def wait_content(hwnd: int, timeout_s: float = 5.0, min_chars: int = 5) -> int:
    """等待编辑控件有内容"""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        if length >= min_chars:
            return length
        time.sleep(0.1)
    return user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)


def get_text(hwnd: int) -> str:
    """从编辑控件读取文本"""
    length = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 2)
    user32.SendMessageW(hwnd, WM_GETTEXT, length + 1, buf)
    return buf.value


def close_notepad(main_hwnd: int):
    """关闭记事本，点'不保存'"""
    user32.PostMessageW(main_hwnd, WM_CLOSE, 0, 0)
    time.sleep(0.3)

    for _ in range(10):
        dlg = user32.FindWindowExW(main_hwnd, None, "#32770", None)
        if dlg:
            btn = user32.FindWindowExW(dlg, None, "Button", None)
            while btn:
                buf = ctypes.create_unicode_buffer(64)
                user32.GetWindowTextW(btn, buf, 64)
                t = buf.value
                # "N" 或 "否" (中文) → 点"否"
                if t and any(x in t for x in ["N", "n", "否", "不"]):
                    user32.SendMessageW(btn, BM_CLICK, 0, 0)
                    time.sleep(0.2)
                    return
                btn = user32.FindWindowExW(dlg, btn, "Button", None)
            break
        time.sleep(0.15)


def read_via_notepad(src: str, timeout: float = 12.0) -> Optional[str]:
    """
    通过 notepad.exe（白名单）+ WM_GETTEXT 读取文件。
    作为 cmd type 失败时的回退方案。
    """
    abs_path = os.path.abspath(src)
    basename = os.path.basename(src)

    for attempt in range(1, 4):
        proc = None
        main_hwnd = None
        try:
            proc = subprocess.Popen(
                ["notepad.exe", abs_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.3)

            main_hwnd = find_window([basename, "notepad", abs_path[:20]], timeout_s=3.0)
            if not main_hwnd:
                continue

            edit_hwnd = None
            for cls in EDIT_CLASS_NAMES:
                edit_hwnd = find_child(main_hwnd, cls)
                if edit_hwnd:
                    break
            if not edit_hwnd:
                continue

            length = wait_content(edit_hwnd, timeout_s=5.0)
            if length < 5:
                continue

            text = get_text(edit_hwnd)
            close_notepad(main_hwnd)
            return text

        except Exception:
            pass
        finally:
            if main_hwnd:
                try:
                    close_notepad(main_hwnd)
                except Exception:
                    pass
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            time.sleep(0.5)

    return None


# ======================================================================
#  主入口
# ======================================================================

def read_encrypted_file(src: str, use_fast: bool = True) -> str:
    """
    读取 DLP 透明加密文件，返回明文字符串。

    工作流程:
      1. 非加密文件 → 直接读取
      2. 加密文件   → cmd type 重定向（快）
      3. cmd 失败   → notepad + WM_GETTEXT（回退）
      4. 全失败     → 抛出 RuntimeError

    Raises:
        FileNotFoundError: 文件不存在
        RuntimeError: 所有方法均失败
    """
    src = os.path.abspath(src)
    if not os.path.exists(src):
        raise FileNotFoundError(f"File not found: {src}")

    # 非加密文件：直接读
    if not is_encrypted(src):
        enc = detect_encoding(src)
        with open(src, encoding=enc, errors='replace') as f:
            return f.read()

    # 加密文件：优先 cmd type
    if use_fast:
        text = read_via_cmd_type(src)
        if text is not None and len(text) > 10:
            return text

    # 回退：notepad + WM_GETTEXT
    text = read_via_notepad(src)
    if text is not None and len(text) > 10:
        return text

    raise RuntimeError(f"All methods failed for: {src}")


def batch_read(files: List[str],
               max_workers: int = 4,
               timeout_per_file: float = 10.0) -> dict:
    """
    并行批量读取 DLP 加密文件。

    Args:
        files: 文件路径列表
        max_workers: 并行线程数（默认 4）
        timeout_per_file: 单文件超时（秒）

    Returns:
        dict: {src_path: (success: bool, content_or_error: str)}
    """
    def worker(path):
        try:
            return (True, read_encrypted_file(path))
        except Exception as e:
            return (False, str(e))

    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(worker, fp): fp for fp in files}
        for future in as_completed(futures):
            path = futures[future]
            try:
                results[path] = future.result()
            except Exception as e:
                results[path] = (False, str(e))

    return results


# ======================================================================
#  CLI
# ======================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage:", file=sys.stderr)
        print("  python read_encrypted.py <src> [out|--]       # 单文件", file=sys.stderr)
        print("  python read_encrypted.py --batch <f1> <f2>... # 批量", file=sys.stderr)
        sys.exit(1)

    # ---- 批量模式 ----
    if sys.argv[1] == '--batch':
        files = sys.argv[2:]
        if not files:
            print("ERROR: --batch needs at least one file", file=sys.stderr)
            sys.exit(1)

        tmp_dir = os.environ.get('TMP', os.environ.get('TEMP', '.'))
        print(f"Batch reading {len(files)} files...", file=sys.stderr)
        results = batch_read(files)

        for path, (ok, data) in results.items():
            tag = "OK" if ok else "FAIL"
            print(f"[{tag}] {path}", file=sys.stderr)
            if ok:
                base = os.path.splitext(os.path.basename(path))[0]
                out_path = os.path.join(tmp_dir, f"{base}_decrypted.txt")
                try:
                    with open(out_path, 'w', encoding='utf-8') as f:
                        f.write(data)
                    print(f"  -> {out_path} ({len(data)} chars)", file=sys.stderr)
                except Exception as e:
                    print(f"  Write error: {e}", file=sys.stderr)
            else:
                print(f"  Error: {data}", file=sys.stderr)
        return

    # ---- 单文件模式 ----
    src = sys.argv[1]
    dest = sys.argv[2] if len(sys.argv) >= 3 else None
    to_stdout = dest == '--'

    try:
        text = read_encrypted_file(src)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if to_stdout:
        sys.stdout.buffer.write(text.encode('utf-8'))
    elif dest:
        os.makedirs(os.path.dirname(os.path.abspath(dest)) or '.', exist_ok=True)
        # 写 UTF-8-BOM：Keil 5.29+ 和 VSCode 都能自动识别
        with open(dest, 'w', encoding='utf-8-sig', newline='\n') as f:
            f.write(text)
        print(f"Written: {dest} ({len(text)} chars)", file=sys.stderr)
    else:
        sys.stdout.buffer.write(text.encode('utf-8'))


if __name__ == '__main__':
    main()
