"""
DLP 原地解密脚本

用于解密后的工程放在 DLP 监控目录下的场景：
- 你修改了解密后的 .c/.h 文件
- 保存时被 DLP 重新加密
- 需要原地解密，保持路径和文件名不变

Usage:
    python inplace_decrypt.py <file1> [file2] ...
    python inplace_decrypt.py --dir <directory> [--ext .c,.h,.s]
    python inplace_decrypt.py --scan <project_root>  # 扫描整个工程，解密所有 DLP 加密文件

Author: OpenClaw Agent
License: MIT
"""
import sys
import os
import tempfile
import subprocess
from typing import Optional, List, Tuple

# 源文件扩展名（需要 GBK 编码检测）
SOURCE_EXTS = {'.c', '.h', '.s', '.inc', '.cpp', '.cxx', '.hpp'}


def is_dlp_encrypted(filepath: str) -> bool:
    """检测文件是否为 DLP 加密格式"""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(128)
            # DLP 加密特征：E-SafeNet 标识或特定魔数
            return b'E-SafeNet' in header or (len(header) >= 4 and 
                   header[0] == 0x62 and header[1] == 0x14 and 
                   header[2] == 0x23 and header[3] == 0x65)
    except Exception:
        return False


def detect_encoding(data: bytes, is_source_file: bool = False) -> str:
    """检测编码，源文件优先 GBK"""
    # UTF-8 BOM
    if data.startswith(b'\xef\xbb\xbf'):
        return 'utf-8-sig'
    
    if is_source_file:
        # 源文件：检查是否有 GBK 中文特征
        has_gbk = any(0x80 <= b <= 0xFF for b in data[:200])
        if has_gbk:
            return 'gbk'
        return 'utf-8'
    
    # 通用检测
    try:
        data.decode('utf-8')
        return 'utf-8'
    except Exception:
        pass
    
    try:
        data.decode('gbk')
        return 'gbk'
    except Exception:
        pass
    
    return 'utf-8'


def decrypt_file_inplace(filepath: str, verbose: bool = True) -> Tuple[bool, str]:
    """
    原地解密单个文件。
    
    Returns:
        (success, message)
    """
    filepath = os.path.abspath(filepath)
    
    if not os.path.exists(filepath):
        return (False, f"文件不存在: {filepath}")
    
    if not is_dlp_encrypted(filepath):
        return (False, f"文件未加密: {filepath}")
    
    # 通过 cmd type 解密
    fd, tmp = tempfile.mkstemp(suffix='.txt')
    os.close(fd)
    
    try:
        # 删除临时文件，让 cmd type 创建
        if os.path.exists(tmp):
            os.remove(tmp)
        
        # cmd /c type src > dst（列表参数保证中文路径正确）
        r = subprocess.run(
            ['cmd', '/c', 'type', filepath, '>', tmp],
            capture_output=True,
            timeout=10.0
        )
        
        if r.returncode != 0:
            return (False, f"cmd type 失败 (code {r.returncode})")
        
        if not os.path.exists(tmp):
            return (False, "临时文件未创建")
        
        # 读取解密内容
        with open(tmp, 'rb') as f:
            decrypted_bytes = f.read()
        
        if is_dlp_encrypted(tmp):
            return (False, "解密失败，内容仍为加密格式")
        
        # 检测编码
        ext = os.path.splitext(filepath)[1].lower()
        is_source = ext in SOURCE_EXTS
        encoding = detect_encoding(decrypted_bytes, is_source_file=is_source)
        
        # 解码
        try:
            text = decrypted_bytes.decode(encoding)
        except Exception:
            text = decrypted_bytes.decode(encoding, errors='replace')
        
        # 写回原文件（UTF-8-BOM）
        with open(filepath, 'wb') as f:
            # BOM
            f.write(b'\xef\xbb\xbf')
            # UTF-8 内容
            f.write(text.encode('utf-8'))
        
        if verbose:
            print(f"[OK] {filepath} ({len(text)} chars, {encoding} -> utf-8-bom)")
        
        return (True, f"解密成功，{len(text)} 字符")
    
    except subprocess.TimeoutExpired:
        return (False, "超时")
    except Exception as e:
        return (False, f"错误: {e}")
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass


def scan_and_decrypt(root: str, extensions: List[str] = None, verbose: bool = True) -> dict:
    """
    扫描目录，原地解密所有 DLP 加密文件。
    
    Args:
        root: 工程根目录
        extensions: 文件扩展名列表，默认 ['.c', '.h', '.s', '.inc']
        verbose: 显示进度
    
    Returns:
        {"success": [...], "failed": [...], "skipped": [...]}
    """
    if extensions is None:
        extensions = ['.c', '.h', '.s', '.inc']
    
    ext_set = set(ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in extensions)
    
    results = {"success": [], "failed": [], "skipped": []}
    
    for dirpath, dirnames, filenames in os.walk(root):
        # 跳过常见非源码目录
        dirnames[:] = [d for d in dirnames if d not in 
                       {'.git', '.svn', '__pycache__', 'node_modules', 'build', 'dist', '.vs'}]
        
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in ext_set:
                continue
            
            fpath = os.path.join(dirpath, fname)
            
            if not is_dlp_encrypted(fpath):
                results["skipped"].append(fpath)
                continue
            
            ok, msg = decrypt_file_inplace(fpath, verbose=verbose)
            if ok:
                results["success"].append(fpath)
            else:
                results["failed"].append((fpath, msg))
    
    return results


def main():
    if len(sys.argv) < 2:
        print("DLP 原地解密工具", file=sys.stderr)
        print("", file=sys.stderr)
        print("用法:", file=sys.stderr)
        print("  python inplace_decrypt.py <file1> [file2] ...      # 解密指定文件", file=sys.stderr)
        print("  python inplace_decrypt.py --scan <project_root>    # 扫描整个工程", file=sys.stderr)
        print("  python inplace_decrypt.py --dir <dir> [--ext .c,.h] # 解密目录内文件", file=sys.stderr)
        print("", file=sys.stderr)
        print("选项:", file=sys.stderr)
        print("  --scan    扫描工程目录，自动解密所有 DLP 加密文件", file=sys.stderr)
        print("  --dir     解密指定目录内的加密文件", file=sys.stderr)
        print("  --ext     指定扩展名，逗号分隔（默认 .c,.h,.s,.inc）", file=sys.stderr)
        sys.exit(1)
    
    args = sys.argv[1:]
    
    # --scan 模式
    if args[0] == '--scan':
        if len(args) < 2:
            print("ERROR: --scan 需要指定工程目录", file=sys.stderr)
            sys.exit(1)
        
        root = args[1]
        if not os.path.isdir(root):
            print(f"ERROR: 目录不存在: {root}", file=sys.stderr)
            sys.exit(1)
        
        # 解析扩展名
        extensions = None
        if '--ext' in args:
            idx = args.index('--ext')
            if idx + 1 < len(args):
                extensions = [e.strip() for e in args[idx + 1].split(',')]
        
        print(f"扫描工程: {root}", file=sys.stderr)
        print(f"扩展名: {extensions or ['.c', '.h', '.s', '.inc']}", file=sys.stderr)
        print("", file=sys.stderr)
        
        results = scan_and_decrypt(root, extensions=extensions)
        
        print("", file=sys.stderr)
        print(f"完成: {len(results['success'])} 成功, {len(results['failed'])} 失败, {len(results['skipped'])} 跳过（未加密）", file=sys.stderr)
        
        if results['failed']:
            print("", file=sys.stderr)
            print("失败文件:", file=sys.stderr)
            for fpath, msg in results['failed']:
                print(f"  {fpath}: {msg}", file=sys.stderr)
        
        sys.exit(0 if not results['failed'] else 1)
    
    # --dir 模式
    if args[0] == '--dir':
        if len(args) < 2:
            print("ERROR: --dir 需要指定目录", file=sys.stderr)
            sys.exit(1)
        
        directory = args[1]
        if not os.path.isdir(directory):
            print(f"ERROR: 目录不存在: {directory}", file=sys.stderr)
            sys.exit(1)
        
        extensions = None
        if '--ext' in args:
            idx = args.index('--ext')
            if idx + 1 < len(args):
                extensions = [e.strip() for e in args[idx + 1].split(',')]
        
        results = scan_and_decrypt(directory, extensions=extensions)
        print(f"完成: {len(results['success'])} 成功, {len(results['failed'])} 失败", file=sys.stderr)
        sys.exit(0 if not results['failed'] else 1)
    
    # 单/多文件模式
    files = args
    success = 0
    failed = 0
    
    for f in files:
        ok, msg = decrypt_file_inplace(f)
        if ok:
            success += 1
        else:
            print(f"[FAIL] {f}: {msg}", file=sys.stderr)
            failed += 1
    
    if len(files) > 1:
        print(f"\n完成: {success} 成功, {failed} 失败", file=sys.stderr)
    
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
