"""
Keil 工程批量解密脚本 v2

支持两种模式：
  1. 全部 DLP 解密（.c/.h/.s/.inc 等）
  2. 源码解密 + 其他文件直接复制（保留 README、.git 等）

Usage:
    python batch_decrypt_keil.py "D:\项目\源目录" "D:\out" --copy-other
    python batch_decrypt_keil.py "D:\项目\源目录" "D:\out" --ext ".c" ".h" --copy-other
"""
import os
import sys
import time
import shutil
import argparse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from read_encrypted import batch_read


# 需要 DLP 解密的扩展名
ENCRYPTED_EXTS = {".c", ".h", ".s", ".inc", ".a", ".lib", ".obj"}

# 编译产物，直接跳过（不复制也不解密）
BUILD_ARTIFACTS = {
    ".o", ".d", ".crf", ".axf", ".hex", ".bin", ".map", ".log",
    ".lst", ".s19", ".dep", ".objlist"
}

# 复制时跳过的目录
SKIP_DIRS = {
    "OBJ", "Listings", "Listing", ".git", ".codeartsdoer", ".workbuddy"
}


def scan_files(src_dir: str, extensions: list, copy_other: bool) -> tuple[list, list]:
    """
    扫描源目录，返回 (需要解密的列表, 需要复制的列表)
    """
    decrypt_files = []
    copy_files = []

    for root, dirs, filenames in os.walk(src_dir):
        # 过滤子目录
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, src_dir)

            # 编译产物直接跳过
            if ext in BUILD_ARTIFACTS:
                continue

            # 需要解密的
            if ext in extensions or fn.lower() in extensions:
                decrypt_files.append(fp)
            elif copy_other:
                # 复制模式：其他文件直接复制（排除 .git 里的文件）
                copy_files.append((fp, rel))

    return decrypt_files, copy_files


def copy_other_files(copy_files: list, src_dir: str, dst_dir: str) -> tuple[int, int, list]:
    """复制非加密文件，返回 (成功数, 失败数, 失败列表)"""
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


def main():
    parser = argparse.ArgumentParser(
        description="Keil 工程批量解密 v2 - 支持源码解密 + 其他文件直接复制",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 源码解密 + 复制 README/.gitignore/文档等（保留完整结构）
  python batch_decrypt_keil.py "D:\\M10" "D:\\M10-Decrypted" --copy-other

  # 只解密 .c/.h（不复制其他文件）
  python batch_decrypt_keil.py "D:\\M10" "D:\\M10-Decrypted"

  # 解密额外类型
  python batch_decrypt_keil.py "D:\\M10" "D:\\out" --ext ".c" ".h" ".s" ".inc" --copy-other
        """
    )
    parser.add_argument("src", help="源目录")
    parser.add_argument("dst", help="目标目录")
    parser.add_argument("--ext", nargs="+",
                        default=[".c", ".h"],
                        help="要解密的扩展名（默认: .c .h）")
    parser.add_argument("--copy-other", action="store_true",
                        help="复制非加密文件（README/.gitignore/文档等）")
    parser.add_argument("-w", "--workers", type=int, default=4,
                        help="并行线程数（默认: 4）")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="单文件超时（默认: 15s）")

    args = parser.parse_args()

    src_dir = os.path.abspath(args.src)
    dst_dir = os.path.abspath(args.dst)

    if not os.path.isdir(src_dir):
        print(f"ERROR: 源目录不存在: {src_dir}", file=sys.stderr)
        sys.exit(1)

    # 扫描文件
    decrypt_files, copy_files = scan_files(src_dir, set(args.ext), args.copy_other)

    print(f"扫描完成：", flush=True)
    print(f"  源码文件（待解密）: {len(decrypt_files)} 个", flush=True)
    if args.copy_other:
        print(f"  其他文件（待复制）: {len(copy_files)} 个", flush=True)
    print(f"  输出目录: {dst_dir}", flush=True)
    print()

    # 阶段1：复制非加密文件（先做，输出结构先建立）
    if args.copy_other and copy_files:
        print(f"[1/2] 复制 {len(copy_files)} 个非加密文件...", flush=True)
        t0 = time.time()
        copy_ok, copy_fail, copy_failed = copy_other_files(copy_files, src_dir, dst_dir)
        print(f"  复制完成: {copy_ok} 成功, {copy_fail} 失败, 耗时 {time.time()-t0:.1f}s", flush=True)
        if copy_failed:
            for fp, err in copy_failed[:5]:
                print(f"    FAIL: {fp} -> {err}", flush=True)
    else:
        copy_ok = copy_fail = 0

    # 阶段2：DLP 解密源码文件
    if decrypt_files:
        print(f"[2/2] 解密 {len(decrypt_files)} 个源码文件（{args.workers} 线程）...", flush=True)
        t0 = time.time()
        results = batch_read(decrypt_files, max_workers=args.workers, timeout_per_file=args.timeout)
        elapsed = time.time() - t0

        ok = fail = 0
        total_chars = 0
        failed_list = []

        for src_path, (success, data) in results.items():
            rel = os.path.relpath(src_path, src_dir)
            out_path = os.path.join(dst_dir, rel)

            if success:
                try:
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
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
            if len(failed_list) > 10:
                print(f"  ... 还有 {len(failed_list)-10} 个")

    print()
    print(f"[OK] 解密完成！输出: {dst_dir}", flush=True)


if __name__ == "__main__":
    main()
