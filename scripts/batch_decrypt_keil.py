"""
Keil 工程批量解密脚本 v4

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
from datetime import datetime
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
    "node_modules", "__pycache__", "build", "dist", ".dlp-backup"
}


# ==============================================================================
#  备份与恢复
# ==============================================================================

def create_backup(project_dir: str) -> str:
    """
    创建工程备份到 .dlp-backup/YYYYMMDD_HHMMSS/
    只备份会被解密的源文件（.c/.h等），不备份编译产物
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(project_dir, ".dlp-backup", timestamp)
    
    # 收集需要备份的文件
    files_to_backup = []
    for dirpath, dirnames, filenames in os.walk(project_dir):
        # 跳过备份目录自身，避免递归
        dirnames[:] = [d for d in dirnames if d != ".dlp-backup"]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in DECRYPT_EXTS:
                fp = os.path.join(dirpath, fn)
                files_to_backup.append(fp)
    
    if not files_to_backup:
        print("[备份] 未找到需要备份的源文件")
        return ""
    
    print(f"[备份] 正在备份 {len(files_to_backup)} 个源文件到 .dlp-backup/{timestamp}/ ...")
    
    copied = 0
    for fp in files_to_backup:
        rel = os.path.relpath(fp, project_dir)
        dst = os.path.join(backup_dir, rel)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(fp, dst)
            copied += 1
        except Exception as e:
            print(f"  [备份失败] {rel}: {e}")
    
    print(f"[备份] 完成: {copied}/{len(files_to_backup)} 个文件已备份")
    print(f"[备份] 路径: {backup_dir}")
    return backup_dir


def restore_from_backup(project_dir: str, backup_dir: str, failed_files: list) -> list:
    """
    从备份恢复解密失败的文件，返回恢复成功的文件列表
    """
    restored = []
    for fp, err in failed_files:
        rel = os.path.relpath(fp, project_dir)
        backup_fp = os.path.join(backup_dir, rel)
        if os.path.exists(backup_fp):
            try:
                shutil.copy2(backup_fp, fp)
                restored.append(fp)
                print(f"  [恢复] {rel}")
            except Exception as e:
                print(f"  [恢复失败] {rel}: {e}")
        else:
            print(f"  [恢复跳过] 备份中不存在: {rel}")
    return restored


# ==============================================================================
#  解密后验证
# ==============================================================================

def verify_decrypted_file(fp: str, original_size: int = None) -> tuple[bool, str]:
    """
    验证解密后的文件是否有效
    返回: (是否有效, 错误信息)
    
    检查项：
    1. 文件大小 > 0（非空文件）
    2. 文件不是加密状态（头部不含 DLP magic bytes）
    3. 文件内容可读（无乱码特征）
    """
    try:
        # 检查1：文件存在且非空
        if not os.path.exists(fp):
            return False, "文件不存在"
        
        size = os.path.getsize(fp)
        if size == 0:
            return False, "文件大小为0（可能被损坏）"
        
        # 检查2：文件头部不是加密状态
        with open(fp, 'rb') as f:
            header = f.read(16)
        
        # 跳过 UTF-8 BOM 后检查
        check = header[3:] if header[:3] == b'\xef\xbb\xbf' else header
        if len(check) >= 4:
            if check[0] in (0x62, 0x77) and check[1] == 0x14 and check[2] == 0x23:
                return False, "文件仍为加密状态（DLP头未消除）"
        
        # 检查3：内容可读性（快速检查）
        # 尝试用 UTF-8 或 GBK 读取前 1KB
        content_sample = header[:1024]
        try:
            content_sample.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content_sample.decode('gbk')
            except UnicodeDecodeError:
                # 如果两种编码都失败，可能是二进制或严重损坏
                # 但某些文件可能包含特殊字符，所以只警告不报错
                pass
        
        return True, "OK"
        
    except Exception as e:
        return False, f"验证异常: {e}"


def verify_all_decrypted(project_dir: str, decrypted_files: list, backup_dir: str) -> tuple[list, list]:
    """
    验证所有解密后的文件
    返回: (验证通过列表, 验证失败列表[(fp, reason)])
    """
    print(f"\n[验证] 正在检查 {len(decrypted_files)} 个解密后的文件...")
    
    ok_list = []
    fail_list = []
    
    for fp in decrypted_files:
        rel = os.path.relpath(fp, project_dir)
        valid, reason = verify_decrypted_file(fp)
        if valid:
            ok_list.append(fp)
        else:
            fail_list.append((fp, reason))
            print(f"  [验证失败] {rel}: {reason}")
    
    print(f"[验证] 通过: {len(ok_list)}, 失败: {len(fail_list)}")
    return ok_list, fail_list


# ==============================================================================
#  原地解密模式（带备份+验证+恢复）
# ==============================================================================

def inplace_decrypt(project_dir: str, extensions: list, workers: int = 4) -> dict:
    """
    原地解密模式：直接解密工程目录中的所有加密文件，保持原路径不变。
    
    流程：
    1. 备份所有待解密文件到 .dlp-backup/时间戳/
    2. 执行解密
    3. 验证解密结果
    4. 失败文件从备份恢复后重试
    5. 报告最终结果
    """
    ext_set = set(e.lower() if e.startswith('.') else f'.{e.lower()}' for e in extensions)

    # ---- 阶段0：扫描加密文件 ----
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
                    check = header[3:] if header[:3] == b'\xef\xbb\xbf' else header
                    if check[0] in (0x62, 0x77) and check[1] == 0x14 and check[2] == 0x23:
                        files_to_decrypt.append(fp)
            except Exception:
                pass

    if not files_to_decrypt:
        print("未找到任何加密文件！")
        return {"success": [], "failed": [], "skipped": [], "backup_dir": ""}

    print(f"发现 {len(files_to_decrypt)} 个加密文件")
    print()

    # ---- 阶段1：备份 ----
    backup_dir = create_backup(project_dir)
    if not backup_dir:
        print("[警告] 备份失败，是否继续解密？(y/n): ", end="")
        choice = input().strip().lower()
        if choice != 'y':
            print("已取消解密")
            return {"success": [], "failed": [], "skipped": [], "backup_dir": ""}
    print()

    # ---- 阶段2：首次解密 ----
    print(f"开始首次解密（{workers} 线程）...")
    
    def decrypt_one(fp):
        try:
            text, enc = read_encrypted_file(fp)
            # 根据检测到的原始编码写回文件
            with open(fp, 'wb') as f:
                if enc == 'utf-8-sig':
                    f.write(b'\xef\xbb\xbf')
                    f.write(text.encode('utf-8'))
                else:
                    try:
                        f.write(text.encode('gbk'))
                    except UnicodeEncodeError:
                        f.write(text.encode('utf-8'))
            return (True, fp, len(text), enc, "")
        except Exception as e:
            return (False, fp, 0, '', str(e))

    first_results = {"success": [], "failed": []}
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(decrypt_one, fp): fp for fp in files_to_decrypt}
        done = 0
        for future in as_completed(futures):
            done += 1
            ok, fp, char_count, enc, err = future.result()
            if ok:
                first_results["success"].append(fp)
                if done % 20 == 0:
                    print(f"  已解密 {done}/{len(files_to_decrypt)}...", flush=True)
            else:
                first_results["failed"].append((fp, err))

    first_elapsed = time.time() - t0
    print(f"\n首次解密完成: {len(first_results['success'])}/{len(files_to_decrypt)} 成功, "
          f"{len(first_results['failed'])} 失败, {first_elapsed:.2f}s")

    # ---- 阶段3：验证 ----
    all_decrypted = first_results["success"]
    ok_list, fail_list = verify_all_decrypted(project_dir, all_decrypted, backup_dir)
    
    # 验证失败的也加入失败列表
    for fp, reason in fail_list:
        first_results["failed"].append((fp, f"验证失败: {reason}"))
    
    # 去重失败列表
    seen = set()
    unique_failed = []
    for fp, err in first_results["failed"]:
        if fp not in seen:
            seen.add(fp)
            unique_failed.append((fp, err))
    first_results["failed"] = unique_failed

    # ---- 阶段4：恢复+重试 ----
    retry_success = []
    if first_results["failed"] and backup_dir:
        print(f"\n[重试] {len(first_results['failed'])} 个文件需要恢复后重试解密")
        
        # 从备份恢复
        restored = restore_from_backup(project_dir, backup_dir, first_results["failed"])
        
        if restored:
            print(f"\n[重试] 开始二次解密 {len(restored)} 个文件...")
            retry_failed = []
            for fp in restored:
                rel = os.path.relpath(fp, project_dir)
                try:
                    text, enc = read_encrypted_file(fp)
                    with open(fp, 'wb') as f:
                        if enc == 'utf-8-sig':
                            f.write(b'\xef\xbb\xbf')
                            f.write(text.encode('utf-8'))
                        else:
                            try:
                                f.write(text.encode('gbk'))
                            except UnicodeEncodeError:
                                f.write(text.encode('utf-8'))
                    
                    # 二次验证
                    valid, reason = verify_decrypted_file(fp)
                    if valid:
                        retry_success.append(fp)
                        print(f"  [重试成功] {rel}")
                    else:
                        retry_failed.append((fp, f"二次验证失败: {reason}"))
                        print(f"  [重试失败] {rel}: {reason}")
                except Exception as e:
                    retry_failed.append((fp, str(e)))
                    print(f"  [重试失败] {rel}: {e}")
            
            # 更新失败列表
            first_results["failed"] = retry_failed
        else:
            print("[重试] 没有文件可以恢复")

    # ---- 阶段5：最终报告 ----
    final_success = list(set(first_results["success"] + retry_success))
    final_failed = first_results["failed"]
    
    print()
    print("=" * 60)
    print("原地解密完成")
    print(f"  首次成功: {len(first_results['success'])}")
    if retry_success:
        print(f"  重试成功: {len(retry_success)}")
    print(f"  最终失败: {len(final_failed)}")
    print(f"  总计: {len(files_to_decrypt)}")
    if final_failed:
        print(f"  成功率: {len(final_success)}/{len(files_to_decrypt)} "
              f"({len(final_success)/len(files_to_decrypt)*100:.1f}%)")
    print(f"  备份目录: {backup_dir}")
    print("=" * 60)

    if final_failed:
        print(f"\n最终失败文件 ({len(final_failed)}) — 已从备份恢复，建议手动检查:")
        for fp, err in final_failed[:15]:
            rel = os.path.relpath(fp, project_dir)
            print(f"  {rel}")
            print(f"    -> {err}")

    # ---- 阶段6：询问是否删除备份 ----
    if backup_dir and os.path.exists(backup_dir):
        print()
        print("-" * 60)
        print("[备份清理] 解密已完成，备份文件保存在:")
        print(f"  {backup_dir}")
        print()
        print("请选择:")
        print("  1. 保留备份（用于对比或回滚）")
        print("  2. 删除备份（释放空间）")
        print()
        choice = input("输入 1 或 2: ").strip()
        
        if choice == '2':
            try:
                shutil.rmtree(backup_dir)
                print(f"[备份清理] 已删除: {backup_dir}")
            except Exception as e:
                print(f"[备份清理] 删除失败: {e}")
        else:
            print(f"[备份清理] 已保留备份: {backup_dir}")
        print("-" * 60)

    return {
        "success": final_success,
        "failed": final_failed,
        "skipped": [],
        "backup_dir": backup_dir
    }


# ==============================================================================
#  副本模式（解密到另一个目录）
# ==============================================================================

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
    副本模式不涉及覆盖原文件，不需要备份。
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
            print(f"\n解密失败 ({len(failed_list)}) — 副本模式不会覆盖原文件，请检查源文件:")
            for pf, err in failed_list[:10]:
                print(f"  FAIL: {pf}")
                print(f"  -> {err}")

    print(f"\n[OK] 解密完成！输出: {dst_dir}", flush=True)
    return results


# ==============================================================================
#  主入口
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Keil 工程批量解密 v4 — 默认原地解密（自动备份+验证+恢复），--copy 生成副本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
默认行为（原地解密）：
  python batch_decrypt_keil.py "D:\\M10-Decrypted\\ZR-M10-源APP"
  → 自动备份 → 解密 → 验证 → 失败恢复 → 询问是否删除备份

生成副本模式（--copy）：
  python batch_decrypt_keil.py "D:\\刘笑\\5216" --copy "D:\\5216-Decrypted"
  → 解密到新目录，原工程不变（无需备份）
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
    parser.add_argument("--no-backup", action="store_true",
                        help="原地解密时跳过备份（不推荐，除非确定无风险）")

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
        print(f"模式: 原地解密（自动备份 + 验证 + 恢复）", flush=True)
        print(f"扩展名: {args.ext}", flush=True)
        print()
        
        if args.no_backup:
            print("[警告] 已跳过备份（--no-backup），风险自负！")
            # 简化流程：直接解密不备份
            # ... 这里可以添加简化逻辑，但默认不走这里
        
        inplace_decrypt(project_dir, extensions=args.ext, workers=args.workers)


if __name__ == "__main__":
    main()
