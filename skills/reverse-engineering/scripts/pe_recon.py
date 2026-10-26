#!/usr/bin/env python
"""PE 秒级侦察：一条命令出齐节表熵/导入/覆盖数据/打包指示器/壳与容器特征。

用法：
    python pe_recon.py <目标.exe> [--json] [--markers extra.txt] [--max-scan N] [--selftest]

依赖分两档，自动选择：
    零依赖档（默认）  仅标准库：格式识别、文件头、节表熵、overlay、入口点与节权限、
                      导入表、打包指示器、通用壳/容器指纹
    增强档（可选）    pip install pefile 后追加：资源树（RT_RCDATA 载荷）、版本信息

退出码：0=无发现；1=有发现（加壳/容器/高熵/异常指示）；2=输入或解析错误。

领域特征（如 WiFi 共享类的 wlanapi/hnetcfg/Tethering）不要写死在这里，用
--markers extra.txt 注入；现成清单见 references/installer-analysis.md「技术路线静态判别」。
输出为紧凑文本报告（--json 时为机器可读结构），供人工研判或直接引用到分析报告的"侦察"一节。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from collections import Counter
from datetime import datetime, timezone

try:  # 可选增强档
    import pefile
except ImportError:
    pefile = None

# ------------------------------------------------------------------ 常量表
GENERIC_MARKERS = [
    (b"NullsoftInst", "NSIS 安装器"),
    (b"Inno Setup", "Inno Setup 安装器"),
    (b"InstallShield", "InstallShield 安装器"),
    (b"7z\xbc\xaf\x27\x1c", "7z 容器（载荷）"),
    (b"MSCF", "CAB 容器"),
    (b"PK\x03\x04", "ZIP 容器"),
    (b"Rar!", "RAR 容器"),
    (b"UPX0", "UPX 壳"),
    (b"UPX!", "UPX 壳"),
    (b".aspack", "ASPack 壳"),
    (b".themida", "Themida 壳"),
    (b".vmp0", "VMProtect 壳"),
    (b"QEXI", "360 QEX 壳"),
]

FILE_MAGIC = [
    (b"\x7fELF", "ELF"),
    (b"MSCF", "CAB 容器"),
    (b"7z\xbc\xaf\x27\x1c", "7z 容器"),
    (b"Rar!", "RAR 容器"),
    (b"PK\x03\x04", "ZIP/APK/JAR/DOCX 等 zip 容器"),
    (b"dex\n035", "Android DEX"),
    (b"\xca\xfe\xba\xbe", "Java class 或 Mach-O universal"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 (LE)"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32 (LE)"),
    (b"%PDF", "PDF"),
    (b"#!", "脚本（shebang）"),
]

MACHINE = {0x014C: "x86 (PE32)", 0x8664: "x64 (PE32+)", 0x01C0: "ARM", 0xAA64: "ARM64"}
SUBSYSTEM = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 7: "POSIX_CUI",
             9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
             12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}
DLLCHAR = [(0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMIC_BASE(ASLR)"),
           (0x0100, "NX_COMPAT(DEP)"), (0x0400, "NO_SEH"), (0x4000, "GUARD_CF(CFG)")]
SEC_READ, SEC_WRITE, SEC_EXEC = 0x40000000, 0x80000000, 0x20000000

ENTROPY_SAMPLE = 8 << 20   # 单节熵采样上限 8MiB，超出只取前 8MiB（报告会标注）
HIGH_ENTROPY = 7.2
MAX_CSTR = 512
MAX_SECTIONS = 96


# ------------------------------------------------------------------ 基础工具
def _u(data: bytes, off: int, size: int, signed: bool = False) -> int:
    if off < 0 or off + size > len(data):
        raise ValueError(f"越界读取 offset=0x{off:X} size={size} filelen={len(data)}")
    return int.from_bytes(data[off:off + size], "little", signed=signed)


def entropy(buf: bytes) -> float:
    """Shannon 熵（bit/byte，0~8）。"""
    if not buf:
        return 0.0
    n = len(buf)
    counts = Counter(buf)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def sniff(data: bytes):
    for magic, name in FILE_MAGIC:
        if data.startswith(magic):
            return name
    return None


def sec_perms(c: int) -> str:
    return ("R" if c & SEC_READ else "-") + ("W" if c & SEC_WRITE else "-") + ("X" if c & SEC_EXEC else "-")


def human_size(n: int) -> str:
    return f"{n:,} bytes"


def force_utf8_console() -> None:
    """Windows 控制台默认可能是 GBK；直接 print 中文/箭头会 UnicodeEncodeError 崩溃。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def sec_name(raw: bytes) -> str:
    """节名：ASCII 原样，非 ASCII 字节转义为 \\xNN（避免乱码与编码崩溃）。"""
    out = []
    for b in raw.rstrip(b"\x00"):
        out.append(chr(b) if 0x20 <= b < 0x7F else f"\\x{b:02X}")
    return "".join(out) or "?"


# ------------------------------------------------------------------ PE 解析（零依赖档）
def parse_sections(data: bytes, coff: int, nsec: int, opt_size: int):
    if nsec > MAX_SECTIONS:
        raise ValueError(f"节表项数量异常（{nsec}），疑似畸形文件")
    base = coff + 20 + opt_size
    out = []
    for i in range(nsec):
        o = base + i * 40
        if o + 40 > len(data):
            raise ValueError(f"第 {i} 个节表项超出文件")
        out.append({
            "name": sec_name(data[o:o + 8]),
            "virtual_size": _u(data, o + 8, 4),
            "virtual_address": _u(data, o + 12, 4),
            "raw_size": _u(data, o + 16, 4),
            "raw_ptr": _u(data, o + 20, 4),
            "characteristics": _u(data, o + 36, 4),
        })
    return out


def parse_headers(data: bytes) -> dict:
    """纯标准库解析 PE 关键头信息；失败抛 ValueError。"""
    if len(data) < 0x40:
        raise ValueError("文件小于 64 字节，不是 PE")
    if data[:2] != b"MZ":
        raise ValueError("缺少 MZ 头，不是 PE")
    e_lfanew = _u(data, 0x3C, 4)
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        raise ValueError(f"e_lfanew 异常（0x{e_lfanew:X}）")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("缺少 PE 签名")
    coff = e_lfanew + 4
    machine = _u(data, coff, 2)
    nsec = _u(data, coff + 2, 2)
    timestamp = _u(data, coff + 4, 4)
    opt_size = _u(data, coff + 16, 2)
    characteristics = _u(data, coff + 18, 2)
    opt = coff + 20
    if opt + opt_size > len(data):
        raise ValueError("可选头超出文件")
    magic = _u(data, opt, 2)
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"未知可选头 Magic 0x{magic:X}（ROM 镜像或畸形）")
    pe32p = magic == 0x20B
    n_dir = _u(data, opt + (108 if pe32p else 92), 4)
    dd_off = opt + (112 if pe32p else 96)
    dirs = []
    for i in range(min(n_dir, 16)):
        o = dd_off + i * 8
        if o + 8 > len(data):
            break
        dirs.append((_u(data, o, 4), _u(data, o + 4, 4)))
    while len(dirs) < 16:
        dirs.append((0, 0))
    return {
        "e_lfanew": e_lfanew,
        "machine": machine,
        "sections_count": nsec,
        "timestamp": timestamp,
        "is_dll": bool(characteristics & 0x2000),
        "pe32p": pe32p,
        "entry_point": _u(data, opt + 16, 4),
        "image_base": _u(data, opt + 24, 8) if pe32p else _u(data, opt + 28, 4),
        "section_alignment": _u(data, opt + 32, 4),
        "file_alignment": _u(data, opt + 36, 4),
        "size_of_image": _u(data, opt + 56, 4),
        "size_of_headers": _u(data, opt + 60, 4),
        "subsystem": _u(data, opt + 68, 2),
        "dll_characteristics": _u(data, opt + 70, 2),
        "dirs": dirs,
        "sections": parse_sections(data, coff, nsec, opt_size),
    }


def rva_to_off(data: bytes, hdr: dict, rva: int):
    if rva < hdr["size_of_headers"] and rva < len(data):
        return rva
    for s in hdr["sections"]:
        span = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= rva < s["virtual_address"] + span:
            delta = rva - s["virtual_address"]
            if delta < s["raw_size"] and s["raw_ptr"] + delta < len(data):
                return s["raw_ptr"] + delta
            return None
    return None


def read_cstr(data: bytes, hdr: dict, rva: int, limit: int = MAX_CSTR):
    off = rva_to_off(data, hdr, rva)
    if off is None:
        return None
    end = data.find(b"\x00", off, min(off + limit, len(data)))
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("latin-1", "replace")


def parse_imports(data: bytes, hdr: dict):
    """零依赖解析导入表；返回 ([{dll, functions}], 错误说明)。"""
    imp_rva, _imp_size = hdr["dirs"][1]
    if not imp_rva:
        return [], None
    off = rva_to_off(data, hdr, imp_rva)
    if off is None:
        return [], "导入表 RVA 无法映射到文件偏移"
    step = 8 if hdr["pe32p"] else 4
    mask = 0x8000000000000000 if hdr["pe32p"] else 0x80000000
    out = []
    for i in range(4096):
        d = off + i * 20
        if d + 20 > len(data):
            break
        orig, _ts, _fwd, name_rva, first = struct.unpack_from("<IIIII", data, d)
        if not (orig or name_rva or first):
            break
        dll = read_cstr(data, hdr, name_rva) if name_rva else None
        funcs = []
        thunk_rva = orig or first
        toff = rva_to_off(data, hdr, thunk_rva) if thunk_rva else None
        if toff is not None:
            for j in range(65536):
                p = toff + j * step
                if p + step > len(data):
                    break
                v = _u(data, p, step)
                if v == 0:
                    break
                if v & mask:
                    funcs.append(f"#{v & 0xFFFF}")
                else:
                    name_rva2 = (v & 0x7FFFFFFF) if not hdr["pe32p"] else v
                    funcs.append(read_cstr(data, hdr, name_rva2 + 2) or "?")
        out.append({"dll": dll or "?", "functions": funcs})
    return out, None


def find_tail(data: bytes, hdr: dict):
    """返回 (overlay 起点, overlay 结束, 证书信息)；证书区不算未知 overlay。"""
    hi = hdr["size_of_headers"]
    for s in hdr["sections"]:
        if s["raw_size"]:
            hi = max(hi, s["raw_ptr"] + s["raw_size"])
    overlay_off = hi if hi < len(data) else None
    cert_off, cert_size = hdr["dirs"][4]
    cert = None
    if cert_size >= 8 and 0 <= cert_off and cert_off + cert_size <= len(data):
        cert = {"offset": cert_off, "size": cert_size}
    overlay_end = len(data)
    if cert is not None and overlay_off is not None and cert["offset"] >= overlay_off:
        overlay_end = cert["offset"]
    return overlay_off, overlay_end, cert


def locate(data: bytes, hdr: dict, off: int, overlay_off, cert) -> str:
    if cert is not None and cert["offset"] <= off < cert["offset"] + cert["size"]:
        return "数字签名证书"
    if overlay_off is not None and off >= overlay_off:
        return "overlay/尾部"
    for s in hdr["sections"]:
        if s["raw_size"] and s["raw_ptr"] <= off < s["raw_ptr"] + s["raw_size"]:
            return f"节 {s['name']}"
    if off < hdr["size_of_headers"]:
        return "PE 头"
    return "未归属"


# ------------------------------------------------------------------ 特征扫描（单遍）
def load_extra_markers(path: str):
    """额外特征文件：每行 `<文本>` 或 `hex:<十六进制>` + TAB + `<含义>`；# 开头为注释。
    按 utf-8-sig 读取，兼容 Windows 编辑器写入的 BOM（否则第一行会带着 BOM 失效）。"""
    extra = []
    with open(path, "r", encoding="utf-8-sig") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                raise ValueError(f"第 {lineno} 行缺少 TAB 分隔：{line!r}")
            raw, label = parts[0].strip(), parts[1].strip()
            if not raw or not label:
                raise ValueError(f"第 {lineno} 行特征或含义为空")
            if raw.lower().startswith("hex:"):
                try:
                    extra.append((bytes.fromhex(raw[4:].strip()), label))
                except ValueError as exc:
                    raise ValueError(f"第 {lineno} 行十六进制非法：{exc}") from exc
            else:
                extra.append((raw.encode("utf-8"), label))
    return extra


def find_markers(data: bytes, markers, max_scan: int = 0):
    """单遍多模式扫描（正则 C 实现），返回 (命中列表, 是否被 max_scan 截断)。"""
    scan = data if (not max_scan or max_scan >= len(data)) else data[:max_scan]
    truncated = len(scan) < len(data)
    if not markers:
        return [], truncated
    label_of = dict(markers)
    pattern = re.compile(b"|".join(re.escape(m) for m, _ in markers))
    found = {}
    for mo in pattern.finditer(scan):
        label = label_of[mo.group(0)]
        rec = found.get(label)
        if rec is None:
            found[label] = {"label": label, "first_offset": mo.start(), "hits": 1}
        else:
            rec["hits"] += 1
    return sorted(found.values(), key=lambda r: r["first_offset"]), truncated


def decode_ver(v) -> str:
    """版本信息字符串：pefile 可能返回 str 或 bytes（多为 UTF-8，纯 ASCII 也可能是 UTF-16LE）。"""
    if isinstance(v, str):
        return v.rstrip()
    if not isinstance(v, (bytes, bytearray)):
        return str(v)
    raw = bytes(v)
    if b"\x00" in raw:
        try:
            return raw.decode("utf-16-le").rstrip("\x00").rstrip()
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8").rstrip()
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace").rstrip()


# ------------------------------------------------------------------ 可选增强档
def pefile_extras(data: bytes):
    """pefile 增强档：资源树（RT_RCDATA 大块）+ 版本信息；失败返回 (None, 原因)。"""
    if pefile is None:
        return None, "未安装 pefile（pip install pefile 后启用增强档）"
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # pefile 异常类型随版本变化，统一兜住
        return None, f"pefile 解析失败：{exc}"
    out = {"resources": [], "resource_types": [], "version": {}}
    try:
        for fi in pe.FileInfo[0]:
            if fi.Key == b"StringFileInfo":
                for st in fi.StringTable:
                    for k, v in st.entries.items():
                        out["version"][decode_ver(k)] = decode_ver(v)
    except Exception:
        pass
    try:
        for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            tname = pefile.RESOURCE_TYPE.get(rt.struct.Id, rt.name or f"type{rt.struct.Id}")
            out["resource_types"].append(str(tname))
            if rt.struct.Id != 10:      # RT_RCDATA：内嵌载荷高发区
                continue
            for rid in rt.directory.entries:
                for lang in rid.directory.entries:
                    d = lang.data.struct
                    if d.Size >= 4096:
                        off = pe.get_offset_from_rva(d.OffsetToData)
                        out["resources"].append({
                            "id": str(rid.name or rid.struct.Id),
                            "size": d.Size,
                            "head": data[off:off + 8].hex() if off is not None else "?",
                        })
    except Exception:
        pass
    try:
        pe.close()
    except Exception:
        pass
    return out, None


# ------------------------------------------------------------------ 主分析
def analyze(path: str, markers=None, max_scan: int = 0) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    rep = {
        "file": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "tier": "stdlib" if pefile is None else "stdlib+pefile",
        "limitations": [],
        "indicators": [],
        "sections": [],
        "markers": [],
    }
    if data[:2] != b"MZ":
        rep["recognized_as"] = sniff(data) or "未识别"
        rep["error"] = "目标不是 PE 文件（本脚本只做 PE 侦察）"
        return rep
    try:
        hdr = parse_headers(data)
    except ValueError as exc:
        rep["error"] = f"PE 解析失败：{exc}"
        return rep

    sections = hdr["sections"]
    ep = hdr["entry_point"]
    entry_sec = "节外（加壳/自解密 stub 强指示）"
    for s in sections:
        span = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= ep < s["virtual_address"] + span:
            entry_sec = f"节 {s['name']}"
            break

    sampled = False
    for s in sections:
        raw = data[s["raw_ptr"]:s["raw_ptr"] + s["raw_size"]] if s["raw_size"] else b""
        if len(raw) > ENTROPY_SAMPLE:
            raw = raw[:ENTROPY_SAMPLE]
            sampled = True
        s["entropy"] = round(entropy(raw), 2) if raw else 0.0
        s["perms"] = sec_perms(s["characteristics"])
        del s["characteristics"]

    rep["identity"] = {
        "machine": MACHINE.get(hdr["machine"], f"0x{hdr['machine']:X}"),
        "kind": "DLL" if hdr["is_dll"] else "EXE",
        "timestamp_utc": datetime.fromtimestamp(hdr["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "entry_point": ep,
        "entry_section": entry_sec,
        "image_base": hdr["image_base"],
        "subsystem": SUBSYSTEM.get(hdr["subsystem"], f"0x{hdr['subsystem']:X}"),
        "dll_characteristics": [name for bit, name in DLLCHAR if hdr["dll_characteristics"] & bit],
        "size_of_image": hdr["size_of_image"],
        "size_of_headers": hdr["size_of_headers"],
        "is_dotnet": bool(hdr["dirs"][14][1]),
        "has_tls_callbacks": bool(hdr["dirs"][9][1]),
        "has_rich_header": b"Rich" in data[:hdr["e_lfanew"]],
    }

    overlay_off, overlay_end, cert = find_tail(data, hdr)
    overlay = None
    if overlay_off is not None and overlay_end > overlay_off:
        tail = data[overlay_off:overlay_end]
        sample = tail[:ENTROPY_SAMPLE]
        preview = sample[:32]
        overlay = {
            "offset": overlay_off,
            "size": len(tail),
            "entropy": round(entropy(sample), 2),
            "head_hex": preview[:16].hex(),
            "nested_pe": tail[:2] == b"MZ",
            "starts_with": sniff(tail) or "未知",
        }
    rep["overlay"] = overlay
    rep["certificate"] = cert

    imports, imp_err = parse_imports(data, hdr)
    rep["imports"] = {
        "dlls": imports,
        "dll_count": len(imports),
        "function_count": sum(len(d["functions"]) for d in imports),
        "error": imp_err,
    }

    rep["sections"] = sections
    if sampled:
        rep["limitations"].append(f"部分节熵按前 {human_size(ENTROPY_SAMPLE)} 采样计算")

    # ---- 打包指示器 ----
    ind = rep["indicators"]
    if not sections:
        ind.append("无节表")
    elif ep and entry_sec.startswith("节外"):
        ind.append("入口点在所有节之外（加壳/自解密 stub 强指示）")
    wx = [s["name"] for s in sections if s["perms"][1] == "W" and s["perms"][2] == "X"]
    if wx:
        ind.append("存在可写+可执行节：" + ", ".join(wx))
    virt = [s["name"] for s in sections if s["raw_size"] == 0 and s["virtual_size"] > 0]
    if virt:
        ind.append("节在磁盘上无数据但运行时占位（运行时解密/虚拟化）：" + ", ".join(virt))
    hi_sec = [f"{s['name']}({s['entropy']:.2f})" for s in sections
              if s["entropy"] > HIGH_ENTROPY and s["raw_size"] > 0x1000]
    if hi_sec:
        ind.append("高熵节（压缩/加密）：" + ", ".join(hi_sec))
    if hdr["dirs"][2][1] and hdr["size_of_image"] and hdr["dirs"][2][1] / hdr["size_of_image"] > 0.8:
        ind.append("资源目录占镜像体积 >80% → 自解压/载荷内嵌型安装器，去资源里找 RCDATA")
    if imp_err:
        ind.append(f"导入表解析异常：{imp_err}")
    elif not imports:
        ind.append("无导入表 → 壳虚拟化/动态解析常见")
    elif rep["imports"]["function_count"] < 10:
        ind.append(f"导入函数极少（{rep['imports']['function_count']} 个）→ 动态解析/加壳常见")
    if hdr["dirs"][14][1]:
        ind.append(".NET 程序集（COM 描述符存在）")
    if overlay and overlay["nested_pe"]:
        ind.append("overlay 内嵌 PE（MZ）→ 捆绑/载荷")
    if overlay and overlay["size"] > 0x1000 and overlay["entropy"] > HIGH_ENTROPY:
        ind.append("overlay 高熵（压缩/加密载荷，安装器/下载器常见）")
    if not any(x for x in rep["identity"]["dll_characteristics"]):
        ind.append("未开启 ASLR/DEP 等缓解（老程序或被壳改写）")

    # ---- 特征扫描 ----
    hits, truncated = find_markers(data, list(GENERIC_MARKERS) + list(markers or []), max_scan)
    for h in hits:
        h["location"] = locate(data, hdr, h["first_offset"], overlay_off, cert)
    rep["markers"] = hits
    if truncated:
        rep["limitations"].append(f"特征扫描被 --max-scan 截断（只扫了前 {human_size(max_scan)}）")

    extras, why = pefile_extras(data)
    rep["pefile"] = extras
    if extras is None:
        rep["limitations"].append(why)
    return rep


# ------------------------------------------------------------------ 文本渲染
def render_text(rep: dict) -> str:
    L = ["== 基本信息 =="]
    L.append(f"  文件     : {rep['file']}")
    L.append(f"  文件大小 : {human_size(rep['size'])}")
    L.append(f"  SHA256   : {rep['sha256']}")
    L.append(f"  MD5      : {rep['md5']}")
    L.append(f"  解析档位 : {rep['tier']}")
    ident = rep["identity"]
    L.append(f"  类型     : {ident['machine']} {ident['kind']}"
             + ("（.NET）" if ident["is_dotnet"] else ""))
    L.append(f"  编译时间 : {ident['timestamp_utc']} UTC（时间戳可伪造，仅参考）")
    L.append(f"  入口点   : RVA 0x{ident['entry_point']:X} → {ident['entry_section']}")
    L.append(f"  ImageBase: 0x{ident['image_base']:X}   子系统: {ident['subsystem']}")
    L.append(f"  缓解特性 : {'、'.join(ident['dll_characteristics']) or '（无）'}"
             + ("   [TLS 回调]" if ident["has_tls_callbacks"] else "")
             + ("   [Rich header]" if ident["has_rich_header"] else ""))

    L.append("== 节表（熵>7.2 视为压缩/加密）==")
    if not rep["sections"]:
        L.append("  （无节表）")
    for s in rep["sections"]:
        flag = "  <-- 高熵" if s["entropy"] > HIGH_ENTROPY and s["raw_size"] > 0x1000 else ""
        L.append(f"  {s['name']:10s} VA=0x{s['virtual_address']:06X} VSize=0x{s['virtual_size']:06X} "
                 f"Raw=0x{s['raw_size']:06X} 熵={s['entropy']:.2f} 权限={s['perms']}{flag}")

    L.append("== 打包/保护指示器 ==")
    if rep["indicators"]:
        L.extend(f"  [!] {x}" for x in rep["indicators"])
    else:
        L.append("  （无）")

    L.append("== 覆盖数据(overlay) ==")
    ov = rep["overlay"]
    if ov:
        L.append(f"  起始 0x{ov['offset']:X}，{human_size(ov['size'])}，熵={ov['entropy']:.2f}，"
                 f"头部 {ov['head_hex']}")
        L.append(f"  起始特征: {ov['starts_with']}" + ("（内嵌 PE！）" if ov["nested_pe"] else ""))
    else:
        L.append("  无")

    L.append("== 数字签名 ==")
    cert = rep["certificate"]
    if cert:
        L.append(f"  有（Authenticode 证书表 @0x{cert['offset']:X}，{human_size(cert['size'])}）")
    else:
        L.append("  无（未签名）")

    L.append("== 导入 DLL ==")
    imp = rep["imports"]
    if imp["error"]:
        L.append(f"  （{imp['error']}）")
    elif not imp["dlls"]:
        L.append("  无导入表（可能被壳虚拟化/动态解析）")
    else:
        L.append(f"  {imp['dll_count']} 个 DLL，{imp['function_count']} 个函数")
        for d in imp["dlls"]:
            names = ", ".join(d["functions"][:12])
            more = f" …(+{len(d['functions']) - 12})" if len(d["functions"]) > 12 else ""
            L.append(f"    {d['dll']}: {names}{more}")

    L.append("== 资源与版本（pefile 增强档）==")
    ex = rep["pefile"]
    if ex is None:
        L.append("  （不可用：pip install pefile 后启用）")
    else:
        L.append(f"  资源类型: {', '.join(ex['resource_types']) or '（无）'}")
        if ex["resources"]:
            L.append("  RT_RCDATA 大块（载荷嫌疑）:")
            for r in ex["resources"][:10]:
                L.append(f"    id={r['id']} {human_size(r['size'])} 头={r['head']}")
        else:
            L.append("  RT_RCDATA 无 ≥4KB 大块")
        for k, v in list(ex["version"].items())[:12]:
            L.append(f"  {k:18s}: {v}")

    L.append("== 容器/安装器/壳/技术路线特征（单遍扫描）==")
    if not rep["markers"]:
        L.append("  （无已知特征）")
    for m in rep["markers"]:
        L.append(f"  [+] {m['label']}: 首个偏移 0x{m['first_offset']:X} 命中 {m['hits']} 处"
                 f"（{m['location']}）")

    if rep["limitations"]:
        L.append("== 覆盖度/限制 ==")
        L.extend(f"  - {x}" for x in rep["limitations"])
    return "\n".join(L)


# ------------------------------------------------------------------ 自检
def _build_fixture() -> bytes:
    """最小合法 PE32：1 节 + 导入表（1 DLL / 1 函数）+ 16 字节 overlay。"""
    e_lfanew, opt_size, nsec = 0x40, 224, 1
    raw_ptr, raw_size = 0x200, 0x200
    buf = bytearray(0x40)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf += b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, nsec, 0x5F5E1000, 0, 0, opt_size, 0x0102)
    oh = bytearray(opt_size)
    struct.pack_into("<H", oh, 0, 0x10B)        # Magic = PE32
    struct.pack_into("<I", oh, 16, 0x1000)      # AddressOfEntryPoint
    struct.pack_into("<I", oh, 20, 0x1000)      # BaseOfCode
    struct.pack_into("<I", oh, 24, 0x2000)      # BaseOfData
    struct.pack_into("<I", oh, 28, 0x400000)    # ImageBase
    struct.pack_into("<I", oh, 32, 0x1000)      # SectionAlignment
    struct.pack_into("<I", oh, 36, 0x200)       # FileAlignment
    struct.pack_into("<I", oh, 56, 0x2000)      # SizeOfImage
    struct.pack_into("<I", oh, 60, raw_ptr)     # SizeOfHeaders
    struct.pack_into("<H", oh, 68, 2)           # Subsystem = GUI
    struct.pack_into("<H", oh, 70, 0x0140)      # DYNAMIC_BASE | NX_COMPAT
    struct.pack_into("<I", oh, 92, 16)          # NumberOfRvaAndSizes
    struct.pack_into("<II", oh, 96 + 8, 0x1010, 0x28)   # 导入表 RVA/Size
    buf += oh
    buf += struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, raw_size, raw_ptr, 0, 0, 0, 0, 0x60000020)
    buf += b"\x00" * (raw_ptr - len(buf))
    sec = bytearray(raw_size)
    # 描述符区占 0x10..0x37（含全零终止项）；thunk 与名字表必须排在它之外，否则会解析出假描述符
    struct.pack_into("<IIIII", sec, 0x10, 0x1040, 0, 0, 0x1050, 0x1048)   # 导入描述符
    struct.pack_into("<II", sec, 0x40, 0x1060, 0)                         # OriginalFirstThunk @RVA 0x1040
    struct.pack_into("<II", sec, 0x48, 0x1060, 0)                         # FirstThunk         @RVA 0x1048
    sec[0x50:0x50 + 13] = b"KERNEL32.dll\x00"                             # DLL 名 @RVA 0x1050
    sec[0x60:0x60 + 14] = b"\x00\x00ExitProcess\x00"                      # hint/name @RVA 0x1060
    buf += sec
    buf += b"OVERLAYPAYLOAD16"
    return bytes(buf)


def selftest() -> int:
    checks = []

    def ck(name, cond):
        checks.append((name, bool(cond)))

    fx = _build_fixture()
    hdr = parse_headers(fx)
    ck("解析 PE32 (x86)", hdr["machine"] == 0x14C and not hdr["pe32p"])
    ck("节表 = ['.text']", [s["name"] for s in hdr["sections"]] == [".text"])
    ck("入口点 0x1000", hdr["entry_point"] == 0x1000)
    ck("ImageBase 0x400000", hdr["image_base"] == 0x400000)
    ck("导入目录 (0x1010,0x28)", hdr["dirs"][1] == (0x1010, 0x28))
    imps, err = parse_imports(fx, hdr)
    ck("导入表解析成功", err is None and len(imps) == 1)
    ck("DLL = KERNEL32.dll", imps and imps[0]["dll"] == "KERNEL32.dll")
    ck("函数 = ['ExitProcess']", imps and imps[0]["functions"] == ["ExitProcess"])
    o_off, o_end, cert = find_tail(fx, hdr)
    ck("overlay 起点 0x400", o_off == 0x400)
    ck("overlay 长度 16", o_end - o_off == 16)
    ck("无证书", cert is None)
    ck("overlay 定位正确", locate(fx, hdr, o_off, o_off, None) == "overlay/尾部")
    mk, _ = find_markers(fx, GENERIC_MARKERS, 0)
    ck("夹具无通用特征命中", mk == [])
    mk2, _ = find_markers(fx, GENERIC_MARKERS + [(b"OVERLAYPAYLOAD16", "测试特征")], 0)
    ck("自定义特征可命中 overlay", len(mk2) == 1 and mk2[0]["label"] == "测试特征")
    ck("熵函数区间", 0.0 <= entropy(b"") <= 0.0 and entropy(bytes(range(256))) > 7.9)
    for bad, why in ((b"", "空文件"), (b"MZ" + b"\x00" * 62, "无 PE 签名"),
                     (b"not a pe at all", "无 MZ")):
        try:
            parse_headers(bad)
            ck(f"拒绝畸形输入：{why}", False)
        except ValueError:
            ck(f"拒绝畸形输入：{why}", True)

    for name, ok in checks:
        print(f"  [{'ok' if ok else 'FAIL'}] {name}")
    passed = sum(1 for _, ok in checks if ok)
    print(f"selftest: {passed}/{len(checks)} 通过")
    return 0 if passed == len(checks) else 2


# ------------------------------------------------------------------ 入口
def main(argv=None) -> int:
    force_utf8_console()
    ap = argparse.ArgumentParser(description="PE 秒级侦察（零依赖档 + 可选 pefile 增强档）")
    ap.add_argument("target", nargs="?", help="目标 PE 文件")
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    ap.add_argument("--markers", metavar="FILE", help="额外特征文件：每行 <文本|hex:十六进制> TAB <含义>")
    ap.add_argument("--max-scan", type=int, default=0, metavar="N", help="特征扫描字节上限（默认全文件）")
    ap.add_argument("--selftest", action="store_true", help="用内置合成 PE 夹具自检解析器")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.target:
        ap.print_help()
        return 2
    try:
        extra = load_extra_markers(args.markers) if args.markers else []
    except (OSError, ValueError) as exc:
        print(f"读取 --markers 失败：{exc}", file=sys.stderr)
        return 2
    try:
        rep = analyze(args.target, markers=extra, max_scan=args.max_scan)
    except OSError as exc:
        print(f"读取文件失败：{exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    elif rep.get("error"):
        print("== 侦察终止 ==")
        print(f"  {rep['error']}")
        if rep.get("recognized_as"):
            print(f"  识别为  : {rep['recognized_as']}")
        print(f"  文件    : {rep['file']}")
        print(f"  SHA256  : {rep['sha256']}")
    else:
        print(render_text(rep))

    if rep.get("error"):
        return 2 if "解析失败" in rep["error"] else 0
    return 1 if (rep["indicators"] or rep["markers"]) else 0


if __name__ == "__main__":
    sys.exit(main())
