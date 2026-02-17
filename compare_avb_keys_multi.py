# compare_avb_keys_multi.py
# 多 PEM 对比 + 识别 Algorithm NONE + 自动识别镜像类型
#
# 示例：
#   python compare_avb_keys_multi.py --key .\pem\testkey_rsa4096.pem --key .\pem\testkey_rsa2048.pem ^
#       --vbmeta .\vbmeta_b.img --vbmeta_system .\vbmeta_system_b.img --boot .\boot_b.img --image .\vendor_boot_b.img
#
# 说明：
# - 私钥侧：avbtool extract_public_key --key <pem> 导出公钥，然后算 sha1/sha256
# - 镜像侧：avbtool info_image --image <img> 解析 top-level key、chain key、algorithm、以及 descriptors 中引用的分区名

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# -------- regex --------
RE_ALGO = re.compile(r"^\s*Algorithm:\s*(.+?)\s*$", re.MULTILINE)
RE_TOP_SHA1 = re.compile(r"^\s*Public key\s*\(sha1\)\s*:\s*([0-9a-fA-F]{40})\s*$", re.MULTILINE)
RE_TOP_SHA256 = re.compile(r"^\s*Public key\s*\(sha256\)\s*:\s*([0-9a-fA-F: \t\r\n]+?)\s*$", re.MULTILINE)

RE_CHAIN_BLOCK = re.compile(r"^\s*Chain Partition descriptor:\s*$", re.MULTILINE)
RE_PART_NAME = re.compile(r"^\s*Partition Name:\s*([A-Za-z0-9_]+)\s*$", re.MULTILINE)
RE_CHAIN_SHA1 = re.compile(r"^\s*Public key\s*\(sha1\)\s*:\s*([0-9a-fA-F]{40})\s*$", re.MULTILINE)
RE_CHAIN_SHA256 = re.compile(r"^\s*Public key\s*\(sha256\)\s*:\s*([0-9a-fA-F: \t\r\n]+?)\s*$", re.MULTILINE)

# descriptors 里引用的分区名（Hash/Hashtree/Chain 都会出现 Partition Name）
RE_ANY_PARTITION_NAME = re.compile(r"^\s*Partition Name:\s*([A-Za-z0-9_]+)\s*$", re.MULTILINE)

def run_avbtool(args_list: List[str]) -> Tuple[int, str, str]:
    avbtool = Path(__file__).with_name("avbtool.py")
    if not avbtool.exists():
        raise FileNotFoundError(f"找不到 avbtool.py：{avbtool}")
    cmd = [sys.executable, str(avbtool)] + args_list
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def hash_file(p: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def clean_sha256(s: str) -> Optional[str]:
    hexstr = re.sub(r"[^0-9a-fA-F]", "", s).lower()
    return hexstr if len(hexstr) == 64 else None

def extract_pubkey_bin_from_pem(pem: Path, out_bin: Path) -> None:
    code, out, err = run_avbtool(["extract_public_key", "--key", str(pem), "--output", str(out_bin)])
    if code != 0:
        raise RuntimeError(f"从 PEM 提取 AVB 公钥失败：{pem}\nSTDOUT:\n{out}\nSTDERR:\n{err}")

def load_keys(pems: List[Path]) -> List[Dict]:
    """
    返回 keys 列表，每个元素：
    {
      "pem": Path,
      "sha1": str,
      "sha256": str
    }
    """
    keys = []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for pem in pems:
            pubbin = td / (pem.stem + ".pub.bin")
            extract_pubkey_bin_from_pem(pem, pubbin)
            keys.append({
                "pem": pem,
                "sha1": hash_file(pubbin, "sha1"),
                "sha256": hash_file(pubbin, "sha256"),
            })
    return keys

def parse_image_info(info_text: str) -> Dict:
    algo = None
    m = RE_ALGO.search(info_text)
    if m:
        algo = m.group(1).strip()

    top_sha1 = None
    m = RE_TOP_SHA1.search(info_text)
    if m:
        top_sha1 = m.group(1).lower()

    top_sha256 = None
    m = RE_TOP_SHA256.search(info_text)
    if m:
        top_sha256 = clean_sha256(m.group(1))

    # chain partitions：用“块扫描”的方式更稳
    chains = []
    lines = info_text.splitlines()
    i = 0
    while i < len(lines):
        if RE_CHAIN_BLOCK.match(lines[i]):
            part = None
            c_sha1 = None
            c_sha256 = None
            j = i + 1
            while j < len(lines):
                line = lines[j]
                # 遇到下一段 descriptor 就停（粗略）
                if "descriptor:" in line and "Chain Partition descriptor" not in line and line.strip().endswith("descriptor:"):
                    break
                if RE_CHAIN_BLOCK.match(line):
                    break

                m = RE_PART_NAME.match(line)
                if m:
                    part = m.group(1)

                m = RE_CHAIN_SHA1.match(line)
                if m:
                    c_sha1 = m.group(1).lower()

                m = RE_CHAIN_SHA256.match(line)
                if m:
                    c_sha256 = clean_sha256(m.group(1))

                j += 1

            chains.append({"partition": part, "sha1": c_sha1, "sha256": c_sha256})
            i = j
        else:
            i += 1

    # descriptors 里引用的所有 Partition Name（帮助你判断“到底验证了谁”）
    referenced_parts = sorted(set(m.group(1) for m in RE_ANY_PARTITION_NAME.finditer(info_text)))

    return {
        "algorithm": algo,
        "top_sha1": top_sha1,
        "top_sha256": top_sha256,
        "chains": chains,
        "referenced_parts": referenced_parts,
        "raw": info_text,
    }

def info_image(path: Path) -> Dict:
    code, out, err = run_avbtool(["info_image", "--image", str(path)])
    if code != 0:
        raise RuntimeError(f"avbtool info_image 失败：{path}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    parsed = parse_image_info(out)
    parsed["stderr"] = err
    return parsed

def best_match(value: Optional[str], keys: List[Dict], field: str) -> List[Path]:
    if not value:
        return []
    hits = []
    for k in keys:
        if k[field].lower() == value.lower():
            hits.append(k["pem"])
    return hits

def fmt_pems(pems: List[Path]) -> str:
    if not pems:
        return "(no match)"
    return " | ".join(str(p.name) for p in pems)

def detect_image_label(path: Path) -> str:
    stem = path.stem.lower()
    stem = re.sub(r"_(a|b)$", "", stem)
    known = [
        "vbmeta_system",
        "vbmeta_vendor",
        "vendor_kernel_boot",
        "vendor_boot",
        "init_boot",
        "vbmeta",
        "boot",
        "dtbo",
    ]
    for k in known:
        if stem == k or stem.startswith(f"{k}_"):
            return k
    return stem

def prompt_existing_paths(title: str) -> List[Path]:
    paths: List[Path] = []
    while True:
        raw = input(f"{title}（为空则下一步）: ").strip()
        if not raw:
            break
        p = Path(raw).expanduser().resolve()
        if not p.exists():
            print(f"[!] 文件不存在：{p}")
            continue
        paths.append(p)
    return paths

def build_image_entries(args: argparse.Namespace) -> List[Tuple[str, Path]]:
    items: List[Tuple[str, Path]] = []
    for name in ("vbmeta", "vbmeta_system", "boot", "dtbo"):
        value = getattr(args, name, None)
        if value:
            p = Path(value).expanduser().resolve()
            items.append((name, p))

    for raw in args.image or []:
        p = Path(raw).expanduser().resolve()
        items.append((detect_image_label(p), p))

    dedup = []
    seen = set()
    for n, p in items:
        if p in seen:
            continue
        seen.add(p)
        dedup.append((n, p))
    return dedup

def main():
    ap = argparse.ArgumentParser(description="多 PEM 对比：分析任意 AVB 镜像的 key（SHA1+SHA256），并识别 Algorithm NONE")
    ap.add_argument("--key", action="append", help="PEM 私钥路径（可重复传多个）")
    ap.add_argument("--vbmeta", help="vbmeta.img 路径（主 vbmeta）")
    ap.add_argument("--vbmeta_system", help="vbmeta_system.img 路径")
    ap.add_argument("--boot", help="boot.img 路径")
    ap.add_argument("--dtbo", help="dtbo.img 路径")
    ap.add_argument("--image", action="append", help="任意 AVB image 路径（可重复传多个，自动识别 vbmeta/boot 等）")
    args = ap.parse_args()

    has_cli_inputs = any([
        args.key,
        args.vbmeta,
        args.vbmeta_system,
        args.boot,
        args.dtbo,
        args.image,
    ])

    if not has_cli_inputs:
        print("未检测到启动参数，进入交互模式。")
        args.key = [str(p) for p in prompt_existing_paths("PEM")]
        args.image = [str(p) for p in prompt_existing_paths("img")]

    # 收集 PEM
    pem_paths = [Path(p).expanduser().resolve() for p in (args.key or [])]
    if not pem_paths:
        print("至少提供一个 PEM（--key 或交互输入）。")
        sys.exit(2)
    for p in pem_paths:
        if not p.exists():
            raise FileNotFoundError(f"找不到 PEM：{p}")

    keys = load_keys(pem_paths)

    print("=== 已加载的 PEM key 指纹 ===")
    for k in keys:
        print(f"- {k['pem'].name}")
        print(f"  sha1   : {k['sha1']}")
        print(f"  sha256 : {k['sha256']}")
    print()

    # 收集镜像
    images = build_image_entries(args)

    if not images:
        print("至少传入一个镜像（推荐 vbmeta + vbmeta_system）。")
        sys.exit(2)

    for name, path in images:
        if not path.exists():
            raise FileNotFoundError(f"找不到镜像 {name}：{path}")

    print("=== 镜像解析与匹配结果 ===")
    for name, img in images:
        parsed = info_image(img)
        algo = parsed["algorithm"] or "(unknown)"

        print("\n" + "=" * 80)
        print(f"[{name}] {img}")
        print("-" * 80)
        print(f"Algorithm            : {algo}")

        # Algorithm NONE：不是报错，而是告诉你“这块本身不带签名”
        if algo.upper() == "NONE":
            print("Note                 : Algorithm NONE 表示该 image 自带的 vbmeta 不签名/不含公钥；是否被验证取决于上级 vbmeta 是否包含它的 hash/hashtree/chain descriptor。")

        # 顶层 key 匹配（如果有）
        top_sha1 = parsed["top_sha1"]
        top_sha256 = parsed["top_sha256"]

        if top_sha1:
            hits = best_match(top_sha1, keys, "sha1")
            print(f"Top pubkey sha1      : {top_sha1}  -> {fmt_pems(hits)}")
        else:
            print("Top pubkey sha1      : (not found)")

        if top_sha256:
            hits = best_match(top_sha256, keys, "sha256")
            print(f"Top pubkey sha256    : {top_sha256}  -> {fmt_pems(hits)}")
        else:
            print("Top pubkey sha256    : (not found)")

        # chain keys（主要出现在 vbmeta）
        if parsed["chains"]:
            print("Chain Partition keys :")
            for c in parsed["chains"]:
                part = c["partition"] or "(unknown)"
                if c["sha1"]:
                    hits = best_match(c["sha1"], keys, "sha1")
                    print(f"  - {part:<14} sha1   : {c['sha1']}  -> {fmt_pems(hits)}")
                else:
                    print(f"  - {part:<14} sha1   : (not found)")
                if c["sha256"]:
                    hits = best_match(c["sha256"], keys, "sha256")
                    print(f"  - {part:<14} sha256 : {c['sha256']}  -> {fmt_pems(hits)}")
                else:
                    print(f"  - {part:<14} sha256 : (not found)")

        # 关键：列出 descriptors 里引用的分区，帮助你判断“到底验证了谁”
        if parsed["referenced_parts"]:
            # 避免太长，只显示前 50 个
            parts = parsed["referenced_parts"]
            show = parts[:50]
            suffix = "" if len(parts) <= 50 else f" ...(+{len(parts)-50})"
            print(f"Referenced partitions: {', '.join(show)}{suffix}")
        else:
            print("Referenced partitions: (none parsed)")

    print("\n提示：如果你确认设备只有 vbmeta + vbmeta_system 两张 vbmeta，理论上它们就足以覆盖 system/vendor/boot/vendor_boot 等多数分区的验证描述。关键是看 descriptors 里有没有提到对应分区。")

    if not has_cli_inputs:
        input("按任意键退出")

if __name__ == "__main__":
    main()
