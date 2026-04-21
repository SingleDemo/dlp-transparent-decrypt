"""
Keil 工程批量解密脚本

适用场景：解密整个 DLP 加密的 Keil 工程目录（包含 .c/.h 源文件），
解密后输出到指定目标目录，保留原目录结构。

原理：read_encrypted.py 的 batch_read() 内部使用 cmd type 重定向，
4 线程并行，实测 413 文件 ~3 秒完成（7.4ms/文件）。

Usage:
    # 基本用法
    python batch_decrypt_keil.py "D:\项目\源目录" "C:\Temp\解密输出"

    # 跳过某些子目录（如 Keil 编译输出）
    python batch_decrypt_keil.py "D:\项目\源目录" "C:\Temp\解密输出" --exclude "OBJ" "Listings" "Listing"

    # 指定文件扩展名
    python batch_decrypt_keil.py "D:\项目\源目录" "C:\Temp\解密输出" --ext ".c" ".h" ".s"

Author: OpenClaw Agent
License: MIT
"""
import os
import sys
import time
import argparse
from pathlib import Path

# 将 scripts/ 加入 path 以便导入 read_encrypted
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from read_encrypted import batch_read


def scan_source(src_dir: str,
                extensions: list[str],
                exclude_dirs: list[str]) -> list[str]:
    """扫描源目录，返回所有匹配扩展名的文件路径列表"""
    files = []
    for root, dirs, filenames in os.walk(src_dir):
        # 过滤掉不需要的子目录（原地修改，os.walk 会使用）
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fn in filenames:
            if any(fn.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, fn))
    return files


def main():
    parser = argparse.ArgumentParser(
        description="Keil 工程批量解密 - 目录对目录，保留结构",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python batch_decrypt_keil.py "D:\\项目\\加密源码" "D:\\项目\\明文源码"
  python batch_decrypt_keil.py "D:\\M10" "D:\\M10-Decrypted" --exclude "OBJ" ".git"
  python batch_decrypt_keil.py "D:\\项目" "D:\\out" --ext ".c" ".h" ".s" ".inc"
        """
    )
    parser.add_argument("src", help="源目录（DLP 加密的 Keil 工程根目录）")
    parser.add_argument("dst", help="目标目录（明文输出，会自动创建）")
    parser.add_argument("--ext", nargs="+", default=[".c", ".h"],
                        help="要解密的文件扩展名（默认: .c .h）")
    parser.add_argument("--exclude", nargs="+",
                        default=["OBJ", "Listings", "Listing", ".git", ".codeartsdoer", ".workbuddy"],
                        help="要跳过的子目录名（默认: OBJ Listings Listing .git 等）")
    parser.add_argument("-w", "--workers", type=int, default=4,
                        help="并行线程数（默认: 4）")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="单文件超时秒数（默认: 15）")

    args = parser.parse_args()

    src_dir = os.path.abspath(args.src)
    dst_dir = os.path.abspath(args.dst)

    if not os.path.isdir(src_dir):
        print(f"ERROR: 源目录不存在: {src_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"扫描源目录: {src_dir}", flush=True)
    files = scan_source(src_dir, args.ext, args.exclude)
    print(f"找到 {len(files)} 个 {'/'.join(args.ext)} 文件", flush=True)

    if not files:
        print("WARNING: 没有找到匹配的文件", file=sys.stderr)
        sys.exit(0)

    print(f"开始批量解密（{args.workers} 线程）...", flush=True)
    t0 = time.time()
    results = batch_read(files, max_workers=args.workers, timeout_per_file=args.timeout)
    elapsed = time.time() - t0

    # 写出结果
    ok_count = fail_count = 0
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
                ok_count += 1
                if ok_count % 50 == 0:
                    print(f"  已解密 {ok_count}/{len(files)}...", flush=True)
            except Exception as e:
                failed_list.append((src_path, str(e)))
                fail_count += 1
        else:
            failed_list.append((src_path, data))
            fail_count += 1

    # 打印报告
    print()
    print("=" * 50)
    print("解密完成")
    print(f"  总计: {len(files)} 文件")
    print(f"  成功: {ok_count}  失败: {fail_count}")
    print(f"  耗时: {elapsed:.2f}s  均速: {elapsed / max(ok_count, 1) * 1000:.1f}ms/文件")
    print(f"  明文: {total_chars / 1024:.0f}KB")
    print(f"  输出: {dst_dir}")
    print("=" * 50)

    if failed_list:
        print(f"\n失败文件 ({len(failed_list)}):")
        for pf, err in failed_list[:10]:
            print(f"  FAIL: {pf}")
            print(f"  -> {err}")
        if len(failed_list) > 10:
            print(f"  ... 还有 {len(failed_list) - 10} 个")


if __name__ == "__main__":
    main()
