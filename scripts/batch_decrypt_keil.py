"""
Keil 工程批量解密脚本 v3

默认行为（原地解密）：
  解密后的工程放在 DLP 监控目录下，修改文件被重新加密后，
  直接对工程目录原地解密，保持路径和文件名不变。

  python batch_decrypt_keil.py "D:\项目\MyProject"

显式生成副本（--copy）：
  python batch_decrypt_keil.py "D:\项目\MyProject" --copy "D:\MyProject-Decrypted"

Author: OpenClaw Agent
License: MIT
"""
import os
import sys
import time
import shutil
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from read_encrypted import batch_read, read_encrypted_file


# 需要 DLP 解密的扩展名
DECRYPT_EXTS = {".c", ".h", ".s", ".inc", ".cpp", ".cxx", ".hpp"}

# 编译产物，跳过不解密
BUILD_ARTIFACTS = {
    ".o", ".d", ".crf", ".axf", ".hex", ".bin", ".map", ".log",
    ".lst", ".s19", ".dep", ".objlist", ".lnp"
}

# 复制模式：跳过的目录
SKIP_DIRS = {
    "OBJ", "Listings", "Listing", ".git", ".codeartsdoer", ".workbuddy",
    "node_modules", "__pycache__", "build", "dist"
}


# ======================================================================
#  原地解密模式
# ======================================================================

def inplace_decrypt(project_dir: str, extensions: list, workers: int = 4) -> dict:
    """
    原地解密模式：直接解密工程目录中的所有加密文件，保持原路径不变。
    """
    ext_set = set(e.lower() if e.startswith('.') else f'.{e.lower()}' for e in extensions)

    files_to_decrypt = []
    for dirpath, dirnames, filenames in os.walk(project_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in ext_set:
                continue
            fp = os.path.join(dirpath, fn)
            # 快速检测是否加密
            try:
                with open(fp, 'rb') as f:
                    header = f.read(8)
                # 检测 DLP 加密头：支持多种变体 (62/77/efbbbf+62 等)
                if len(header) >= 4:
                    # 跳过 UTF-8 BOM 后检查加密头
                    check = header[3:] if header[:3] == b'\xef\xbb\xbf' else header
                    if check[0] in (0x62, 0x77) and check[1] == 0x14 and check[2] == 0x23:
                        files_to_decrypt.append(fp)
            except Exception:
                pass

    if not files_to_decrypt:
        print("未找到任何加密文件！")
        return {"success": [], "failed": [], "skipped": []}

    print(f"发现 {len(files_to_decrypt)} 个加密文件，开始原地解密...", flush=True)

    def decrypt_one(fp):
        try:
            text, enc = read_encrypted_file(fp)
            # 根据检测到的原始编码写回文件
            # utf-8-sig: 带 BOM 的 UTF-8
            # utf-8: 无 BOM 的 UTF-8
            # gbk: GBK/GB2312 编码（Keil 默认）
            with open(fp, 'wb') as f:
                if enc == 'utf-8-sig':
                    f.write(b'\xef\xbb\xbf')
                    f.write(text.encode('utf-8'))
                elif enc == 'gbk':
                    f.write(text.encode('gbk'))
                else:
                    f.write(text.encode('utf-8'))
            return (True, fp, len(text), enc)
        except Exception as e:
            return (False, fp, str(e), '')

    results = {"success": [], "failed": [], "skipped": []}
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(decrypt_one, fp): fp for fp in files_to_decrypt}
        done = 0
        for future in as_completed(futures):
            done += 1
            ok, fp, data, enc = future.result()
            if ok:
                results["success"].append(fp)
                if done % 20 == 0:
                    print(f"  已解密 {done}/{len(files_to_decrypt)}...", flush=True)
            else:
                results["failed"].append((fp, data))

    elapsed = time.time() - t0
    total_chars = sum(os.path.getsize(fp) for fp in results["success"]) if results["success"] else 0

    print()
    print("=" * 55)
    print("原地解密完成")
    print(f"  成功: {len(results['success'])} / {len(files_to_decrypt)}")
    print(f"  失败: {len(results['failed'])}")
    print(f"  耗时: {elapsed:.2f}s  均速: {elapsed/max(len(results['success']),1)*1000:.1f}ms/文件")
    print(f"  目录: {project_dir}")
    print("=" * 55)

    if results["failed"]:
        print(f"\n解密失败 ({len(results['failed'])}):")
        for fp, err in results["failed"][:10]:
            print(f"  {fp}: {err}")

    return results


# ======================================================================
#  副本模式（解密到另一个目录）
# ======================================================================

def scan_files(src_dir: str, extensions: list, copy_other: bool) -> tuple[list, list]:
    """
    扫描源目录，返回 (需要解密的列表, 需要复制的列表)
    """
    ext_set = set(e.lower() if e.startswith('.') else f'.{e.lower()}' for e in extensions)
    decrypt_files = []
    copy_files = []

    for root, dirs, filenames in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, src_dir)

            if ext in BUILD_ARTIFACTS:
                continue

            if ext in ext_set or fn.lower() in ext_set:
                decrypt_files.append(fp)
            elif copy_other:
                copy_files.append((fp, rel))

    return decrypt_files, copy_files


def copy_other_files(copy_files: list, src_dir: str, dst_dir: str) -> tuple[int, int, list]:
    """复制非加密文件"""
    ok = fail = 0
    failed = []
    for src_path, rel in copy_files:
        dst_path = os.path.join(dst_dir, rel)
        try:
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            shutil.copy2(src_path, dst_path)
            ok += 1
        except Exception as e:
            failed.append((src_path, str(e)))
            fail += 1
    return ok, fail, failed


def copy_decrypt(src_dir: str, dst_dir: str, extensions: list,
                 copy_other: bool, workers: int = 4, timeout: float = 15.0) -> dict:
    """
    副本模式：将工程解密复制到目标目录。
    """
    decrypt_files, copy_files = scan_files(src_dir, extensions, copy_other)

    print(f"扫描完成：", flush=True)
    print(f"  源码文件（待解密）: {len(decrypt_files)} 个", flush=True)
    if copy_other:
        print(f"  其他文件（待复制）: {len(copy_files)} 个", flush=True)
    print(f"  输出目录: {dst_dir}", flush=True)
    print()

    # 阶段1：复制非加密文件
    copy_ok = copy_fail = 0
    if copy_other and copy_files:
        print(f"[1/2] 复制 {len(copy_files)} 个非加密文件...", flush=True)
        t0 = time.time()
        copy_ok, copy_fail, _ = copy_other_files(copy_files, src_dir, dst_dir)
        print(f"  完成: {copy_ok} 成功, {copy_fail} 失败, {time.time()-t0:.1f}s", flush=True)

    # 阶段2：DLP 解密
    results = {"success": [], "failed": []}
    if decrypt_files:
        print(f"[2/2] 解密 {len(decrypt_files)} 个源码文件（{workers} 线程）...", flush=True)
        t0 = time.time()
        batch_results = batch_read(decrypt_files, max_workers=workers, timeout_per_file=timeout)

        ok = fail = 0
        total_chars = 0
        failed_list = []

        for src_path, (success, data, enc) in batch_results.items():
            rel = os.path.relpath(src_path, src_dir)
            out_path = os.path.join(dst_dir, rel)

            if success:
                try:
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    # 根据检测到的原始编码写入副本
                    write_enc = 'utf-8-sig' if enc == 'utf-8-sig' else ('gbk' if enc == 'gbk' else 'utf-8')
                    with open(out_path, "w", encoding=write_enc, newline="\n") as f:
                        f.write(data)
                    total_chars += len(data)
                    ok += 1
                    if ok % 50 == 0:
                        print(f"  已解密 {ok}/{len(decrypt_files)}...", flush=True)
                except Exception as e:
                    failed_list.append((src_path, str(e)))
                    fail += 1
            else:
                failed_list.append((src_path, data))
                fail += 1

        results["success"] = [p for p, (suc, _, _) in [(s, batch_results[s]) for s in batch_results] if suc]
        results["failed"] = failed_list

        elapsed = time.time() - t0
        print()
        print("=" * 55)
        print("解密完成")
        print(f"  源码解密: {ok}/{len(decrypt_files)} 成功  ({fail} 失败)")
        print(f"  其他复制: {copy_ok}/{len(copy_files)} 成功  ({copy_fail} 失败)")
        print(f"  源码耗时: {elapsed:.2f}s  均速: {elapsed/max(ok,1)*1000:.1f}ms/文件")
        print(f"  明文总量: {total_chars/1024:.0f}KB")
        print(f"  输出目录: {dst_dir}")
        print("=" * 55)

        if failed_list:
            print(f"\n解密失败 ({len(failed_list)}):")
            for pf, err in failed_list[:10]:
                print(f"  FAIL: {pf}")
                print(f"  -> {err}")

    print(f"\n[OK] 解密完成！输出: {dst_dir}", flush=True)
    return results


# ======================================================================
#  主入口
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Keil 工程批量解密 v3 — 默认原地解密，--copy 生成副本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
默认行为（原地解密）：
  python batch_decrypt_keil.py "D:\\M10-Decrypted\\ZR-M10-源APP"
  → 直接解密工程目录中的所有 DLP 加密文件，保持原路径不变

生成副本模式（--copy）：
  python batch_decrypt_keil.py "D:\\刘笑\\5216" --copy "D:\\5216-Decrypted"
  → 解密到新目录，原工程不变
"""
    )
    parser.add_argument("project", help="工程目录（默认原地解密）")
    parser.add_argument("--copy", metavar="DST",
                        help="解密副本模式：将解密后的工程复制到目标目录，原工程不变")
    parser.add_argument("--copy-other", action="store_true",
                        help="副本模式时，同时复制非加密文件（README/.gitignore/文档等）")
    parser.add_argument("--ext", nargs="+",
                        default=[".c", ".h"],
                        help="要处理的扩展名（默认: .c .h）")
    parser.add_argument("-w", "--workers", type=int, default=4,
                        help="并行线程数（默认: 4）")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="单文件超时（默认: 15s）")

    args = parser.parse_args()

    project_dir = os.path.abspath(args.project)

    if not os.path.isdir(project_dir):
        print(f"ERROR: 目录不存在: {project_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"工程目录: {project_dir}", flush=True)

    if args.copy:
        # === 副本模式 ===
        dst_dir = os.path.abspath(args.copy)
        print(f"模式: 副本解密 -> {dst_dir}", flush=True)
        copy_decrypt(project_dir, dst_dir,
                     extensions=args.ext,
                     copy_other=args.copy_other,
                     workers=args.workers,
                     timeout=args.timeout)
    else:
        # === 原地解密模式（默认）===
        print(f"模式: 原地解密（直接修改工程目录中的文件）", flush=True)
        print(f"扩展名: {args.ext}", flush=True)
        print()
        inplace_decrypt(project_dir, extensions=args.ext, workers=args.workers)


if __name__ == "__main__":
    main()
