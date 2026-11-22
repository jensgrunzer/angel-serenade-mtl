import argparse
import json
import re
import shutil
import struct
from pathlib import Path

BASE = Path(r"C:\Games\KOGADO\AS")
SCRIPT_DIR = BASE / "Script"
JSON_DIR = BASE / "tl_json"
PAK_PATH = BASE / "Script.pak"
PAK_ORIG = BASE / "Script.pak.orig"
ALL_JSON = BASE / "ALL_SCRIPTS.json"
ALL_MAP = BASE / "ALL_SCRIPTS_MAP.json"
DEFAULT_TOKEN_OUT = BASE / "ALL_SCRIPTS_OUT.json"
QC_REPORT = BASE / "qc_report.txt"

MAX_COLS = 48
LINE4_ICON_SAFE_COLS = 42

TWO_BYTE_OPS = {
    0x000E, 0x000F, 0x0010, 0x0012, 0x0016, 0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001E,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0045, 0x0046, 0x0047, 0x0048, 0x004A, 0x004B, 0x004C,
    0x0081,
}
SIX_BYTE_OPS = {0x0001, 0x0004, 0x0005, 0x0007}
JUMP_OPS = {0x0004, 0x0005, 0x0007}
TEXT_OPS = {0x0002, 0x0080, 0x0082, 0x0084}

_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x8408 if (_c & 1) else (_c >> 1)
    _CRC_TABLE.append(_c)

def crc16_kogado(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]
    return crc

def sanitize_sjis(text: str) -> str:
    rep = {
        "\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'",
        "\u2014": "--", "\u2013": "-", "\u2026": "...", "\u00a0": " ",
        "\u2212": "-", "\r\n": "\n", "\r": "\n",
    }
    for k, v in rep.items():
        text = text.replace(k, v)
    return text

def str_cols(s: str, token_cols: int = 12) -> int:
    s_norm = s.replace("%n", "N" * token_cols).replace("%s", "S" * token_cols)
    return len(s_norm.encode("cp932", errors="replace"))

def word_wrap_box(text: str, max_cols: int = MAX_COLS) -> str:
    had_trailing_nl = text.endswith("\n")
    paras = text.rstrip("\n").split("\n") if text.rstrip("\n") else [""]
    out_lines = []
    for p in paras:
        if not p:
            out_lines.append("")
            continue
        words = p.split(" ")
        cur = ""
        for w in words:
            if not cur:
                cur = w
            elif str_cols(cur + " " + w) <= max_cols:
                cur += " " + w
            else:
                out_lines.append(cur)
                cur = w
        if cur or out_lines:
            out_lines.append(cur)
    res = "\n".join(out_lines)
    if had_trailing_nl:
        res += "\n"
    return res

def format_for_engine(en: str, orig_jp: str, op_hex: str) -> str:
    s = sanitize_sjis(en)
    if orig_jp.endswith("\n") and not s.endswith("\n"):
        s += "\n"
    if op_hex in ("0x0080", "0x0084"):
        s = word_wrap_box(s, MAX_COLS)
    return s

# ---------------- WPS Binary Codec ---------------- #

class Insn:
    __slots__ = ("old_ip", "new_ip", "op", "kind", "raw", "arg", "text_bytes", "jump_target_old")
    def __init__(self, old_ip, op, kind, raw=b"", arg=0, text_bytes=b"", jump_target_old=None):
        self.old_ip = old_ip
        self.new_ip = 0
        self.op = op
        self.kind = kind
        self.raw = raw
        self.arg = arg
        self.text_bytes = text_bytes
        self.jump_target_old = jump_target_old

def parse_wps(data: bytes):
    assert data[:4] == b"AS01"
    file_size, unk_08, ft_lo, ft_hi, s1_off, s1_sz, s2_off, s2_sz, unk_24 = struct.unpack_from("<9I", data, 4)
    assert s1_off == 0x28 and s1_off + s1_sz == s2_off and s2_off + s2_sz == len(data)

    sec1 = []
    pos = s1_off
    while pos < s2_off:
        rec_sz, unk1, fn_off, tag = struct.unpack_from("<HHII", data, pos)
        sec1.append([rec_sz, unk1, fn_off, tag, data[pos + 12 : pos + rec_sz]])
        pos += rec_sz

    blocks = []
    ip_to_insn = {}
    pos = s2_off
    while pos < len(data):
        blk_sz, fn_len, code_sz = struct.unpack_from("<3I", data, pos)
        fn_bytes = data[pos + 12 : pos + 12 + fn_len]
        code_start = pos + 12 + fn_len
        code_end = code_start + code_sz
        pad_len = blk_sz - (12 + fn_len + code_sz)

        insns = []
        ip = code_start
        while ip < code_end:
            op = struct.unpack_from("<H", data, ip)[0]
            if op in TWO_BYTE_OPS or (0x0100 <= op <= 0x01FF):
                insn = Insn(ip, op, "2", raw=data[ip:ip+2])
                ip += 2
            elif op in SIX_BYTE_OPS:
                if op in JUMP_OPS:
                    rel = struct.unpack_from("<i", data, ip + 2)[0]
                    insn = Insn(ip, op, "jmp", jump_target_old=ip + rel)
                else:
                    insn = Insn(ip, op, "6", raw=data[ip:ip+6])
                ip += 6
            elif op in (0x0002, 0x0008, 0x0082):
                slen = struct.unpack_from("<I", data, ip + 2)[0]
                insn = Insn(ip, op, "str", text_bytes=data[ip + 6 : ip + 6 + slen])
                ip += 6 + slen
            elif op in (0x0080, 0x0084):
                line_id = struct.unpack_from("<I", data, ip + 2)[0]
                slen = struct.unpack_from("<I", data, ip + 6)[0]
                insn = Insn(ip, op, "idstr", arg=line_id, text_bytes=data[ip + 10 : ip + 10 + slen])
                ip += 10 + slen
            else:
                raise ValueError(f"Unknown opcode 0x{op:04X} at 0x{ip:X}")
            ip_to_insn[insn.old_ip] = insn
            insns.append(insn)

        assert ip == code_end
        blocks.append({
            "old_code_start_rel": code_start - s2_off,
            "old_code_sz": code_sz,
            "fn_bytes": fn_bytes,
            "pad_len": pad_len,
            "insns": insns,
        })
        pos += blk_sz

    return {
        "unk_08": unk_08, "ft_lo": ft_lo, "ft_hi": ft_hi, "unk_24": unk_24,
        "sec1": sec1, "blocks": blocks, "ip_to_insn": ip_to_insn,
    }

def build_wps(parsed, replacements=None) -> bytes:
    if replacements:
        idx = 0
        for blk in parsed["blocks"]:
            for insn in blk["insns"]:
                if insn.op in TEXT_OPS:
                    if idx in replacements and replacements[idx]:
                        orig_jp = insn.text_bytes.rstrip(b"\x00").decode("cp932", errors="replace")
                        s = format_for_engine(replacements[idx], orig_jp, f"0x{insn.op:04X}")
                        insn.text_bytes = s.encode("cp932", errors="replace") + b"\x00"
                    idx += 1

    s1_sz = sum(r[0] for r in parsed["sec1"])
    s2_off = 0x28 + s1_sz
    cur = s2_off
    old_rel_to_new_rel = {}

    for blk in parsed["blocks"]:
        fn_len = len(blk["fn_bytes"])
        code_start = cur + 12 + fn_len
        old_rel_to_new_rel[blk["old_code_start_rel"]] = code_start - s2_off
        ip = code_start
        for insn in blk["insns"]:
            insn.new_ip = ip
            if insn.kind == "2":
                ip += 2
            elif insn.kind in ("6", "jmp"):
                ip += 6
            elif insn.kind == "str":
                ip += 6 + len(insn.text_bytes)
            elif insn.kind == "idstr":
                ip += 10 + len(insn.text_bytes)
        new_code_sz = ip - code_start
        blk["new_code_sz"] = new_code_sz
        raw_blk_sz = 12 + fn_len + new_code_sz
        blk["new_blk_sz"] = (raw_blk_sz + blk["pad_len"]) if new_code_sz == blk["old_code_sz"] else (((raw_blk_sz + 15) // 16) * 16)
        cur += blk["new_blk_sz"]

    sec1_out = bytearray()
    for rec_sz, unk1, fn_off, tag, rest in parsed["sec1"]:
        sec1_out += struct.pack("<HHII", rec_sz, unk1, old_rel_to_new_rel[fn_off], tag) + rest

    ip_to_insn = parsed["ip_to_insn"]
    sec2_out = bytearray()
    for blk in parsed["blocks"]:
        fn_len = len(blk["fn_bytes"])
        sec2_out += struct.pack("<3I", blk["new_blk_sz"], fn_len, blk["new_code_sz"]) + blk["fn_bytes"]
        for insn in blk["insns"]:
            if insn.kind in ("2", "6"):
                sec2_out += insn.raw
            elif insn.kind == "jmp":
                sec2_out += struct.pack("<Hi", insn.op, ip_to_insn[insn.jump_target_old].new_ip - insn.new_ip)
            elif insn.kind == "str":
                sec2_out += struct.pack("<HI", insn.op, len(insn.text_bytes)) + insn.text_bytes
            elif insn.kind == "idstr":
                sec2_out += struct.pack("<HII", insn.op, insn.arg, len(insn.text_bytes)) + insn.text_bytes
        sec2_out += b"\x00" * (blk["new_blk_sz"] - (12 + fn_len + blk["new_code_sz"]))

    total_sz = 0x28 + len(sec1_out) + len(sec2_out)
    hdr = struct.pack(
        "<4s9I", b"AS01", total_sz, parsed["unk_08"], parsed["ft_lo"], parsed["ft_hi"],
        0x28, len(sec1_out), s2_off, len(sec2_out), parsed["unk_24"]
    )
    return hdr + sec1_out + sec2_out

def pack_script_pak(wps_map: dict, out_pak: Path):
    orig = PAK_ORIG.read_bytes() if PAK_ORIG.exists() else PAK_PATH.read_bytes()
    idx_off = 0x10 + struct.unpack_from("<I", orig, 8)[0]
    cnt = struct.unpack_from("<I", orig, 12)[0]

    body = bytearray()
    index = bytearray()
    for i in range(cnt):
        o = idx_off + i * 48
        raw_name24 = orig[o : o + 24]
        stem = orig[o : o + 21].split(b"\x00")[0].decode("cp932")
        ext = orig[o + 21 : o + 24].split(b"\x00")[0].decode("cp932")
        fname = f"{stem}.{ext}"
        ft_bytes = orig[o + 40 : o + 48]

        fdata = wps_map[fname]
        rel_off = len(body)
        crc = crc16_kogado(fdata)
        body += fdata
        if len(body) % 16:
            body += b"\x00" * (16 - (len(body) % 16))

        index += raw_name24 + struct.pack("<IIIBBH", rel_off, len(fdata), len(fdata), 0, 1, crc) + ft_bytes

    hdr = struct.pack("<6sHII", b"HyPack", 0x0300, len(body), cnt)
    full = hdr + body + index
    full += struct.pack("<H", crc16_kogado(full))
    out_pak.write_bytes(full)

# ---------------- JSON / Token Helpers ---------------- #

def write_all_json(items: list[dict]):
    with ALL_JSON.open("w", encoding="utf-8") as fp:
        fp.write("[\n")
        for i, item in enumerate(items):
            comma = "," if i + 1 < len(items) else ""
            fp.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + comma + "\n")
        fp.write("]\n")

def build_global_mapping() -> list[dict]:
    if ALL_MAP.exists():
        mapping = json.loads(ALL_MAP.read_text(encoding="utf-8"))
        if mapping and "op" in mapping[0] and "jp" in mapping[0]:
            return mapping
    mapping = []
    g = 0
    for jpath in sorted(JSON_DIR.glob("*.json")):
        data = json.loads(jpath.read_text(encoding="utf-8"))
        for e in data["entries"]:
            mapping.append({"g": g, "json_file": jpath.name, "id": e["id"], "op": e["op"], "jp": e["jp"]})
            g += 1
    ALL_MAP.write_text(json.dumps(mapping, ensure_ascii=False), encoding="utf-8")
    return mapping

def strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z0-9_-]*\s*\n", "", text)
    text = re.sub(r"\n```\s*$", "", text)
    return text.strip()

def parse_token_or_any_json(text: str) -> dict[int, str]:
    text = strip_fences(text)
    translations: dict[int, str] = {}

    def ingest_obj(obj):
        if isinstance(obj, dict):
            for k in ("entries", "items"):
                if k in obj and isinstance(obj[k], list):
                    ingest_obj(obj[k])
                    return
            if "g" in obj and "en" in obj:
                translations[int(obj["g"])] = str(obj["en"])
            else:
                for k, v in obj.items():
                    if str(k).isdigit() and isinstance(v, str):
                        translations[int(k)] = v
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    translations[int(item[0])] = str(item[1])
                elif isinstance(item, dict) and "g" in item and "en" in item:
                    translations[int(item["g"])] = str(item["en"])

    try:
        ingest_obj(json.loads(text))
        if translations:
            return translations
    except json.JSONDecodeError:
        pass

    for raw_line in text.splitlines():
        line = raw_line.strip().rstrip(",")
        if not line or line in ("[", "]", "{", "}") or line.startswith("```"):
            continue
        try:
            ingest_obj(json.loads(line))
            continue
        except json.JSONDecodeError:
            pass
        if re.match(r'^"\d+"\s*:', line):
            try:
                ingest_obj(json.loads("{" + line + "}"))
            except json.JSONDecodeError:
                pass
    return translations

def compress_ranges(nums: list[int]) -> str:
    if not nums:
        return "none"
    ranges = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
        else:
            ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
            start = prev = n
    ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
    return ", ".join(ranges[:15]) + (" ..." if len(ranges) > 15 else "")

def resolve_files(paths: list[str], default_path: Path) -> list[Path]:
    if not paths:
        if not default_path.exists():
            raise FileNotFoundError(f"Default file not found: {default_path}")
        return [default_path]
    out = []
    for arg in paths:
        p = Path(arg)
        if "*" in arg or "?" in arg:
            out.extend(sorted(p.parent.glob(p.name)))
        else:
            out.append(p)
    return out

# ---------------- Commands ---------------- #

def do_test():
    ok = 0
    for p in sorted(SCRIPT_DIR.glob("*.Wps")):
        raw = p.read_bytes()
        assert build_wps(parse_wps(raw)) == raw, f"Roundtrip mismatch on {p.name}"
        ok += 1
    pak = PAK_ORIG.read_bytes() if PAK_ORIG.exists() else PAK_PATH.read_bytes()
    assert crc16_kogado(pak[:-2]) == struct.unpack_from("<H", pak, len(pak) - 2)[0]
    print(f"[test] PASS: {ok}/145 .Wps files roundtripped byte-for-byte + Script.pak CRC16 ok.")

def do_extract(force: bool = False):
    JSON_DIR.mkdir(exist_ok=True)
    written = skipped = total_lines = 0
    for p in sorted(SCRIPT_DIR.glob("*.Wps")):
        parsed = parse_wps(p.read_bytes())
        entries = []
        idx = 0
        for blk in parsed["blocks"]:
            for insn in blk["insns"]:
                if insn.op in TEXT_OPS:
                    jp = insn.text_bytes.rstrip(b"\x00").decode("cp932", errors="replace")
                    entries.append({"id": idx, "op": f"0x{insn.op:04X}", "jp": jp, "en": ""})
                    idx += 1
        if entries:
            out = JSON_DIR / f"{p.stem}.json"
            total_lines += len(entries)
            if out.exists() and not force:
                skipped += 1
                continue
            out.write_text(json.dumps({"file": p.name, "entries": entries}, ensure_ascii=False, indent=2), encoding="utf-8")
            written += 1
    print(f"[extract] {total_lines} lines total (wrote {written}, skipped {skipped} existing in {JSON_DIR}).")

def do_gather():
    items = []
    mapping = []
    g = 0
    jfiles = sorted(JSON_DIR.glob("*.json"))
    for jpath in jfiles:
        data = json.loads(jpath.read_text(encoding="utf-8"))
        src_file = data["file"]
        for e in data["entries"]:
            items.append({"g": g, "f": src_file, "id": e["id"], "op": e["op"], "jp": e["jp"], "en": e.get("en", "")})
            mapping.append({"g": g, "json_file": jpath.name, "id": e["id"], "op": e["op"], "jp": e["jp"]})
            g += 1

    write_all_json(items)
    ALL_MAP.write_text(json.dumps(mapping, ensure_ascii=False), encoding="utf-8")
    mb = ALL_JSON.stat().st_size / (1024 * 1024)
    print(f"[gather] {len(items)} entries from {len(jfiles)} files -> {ALL_JSON.name} ({mb:.2f} MB)")

def do_import_token(file_args: list[str]):
    if not ALL_JSON.exists():
        print("[import-token] ALL_SCRIPTS.json not found, running gather first...")
        do_gather()
    files = resolve_files(file_args, DEFAULT_TOKEN_OUT)
    all_tl: dict[int, str] = {}
    for f in files:
        parsed = parse_token_or_any_json(f.read_text(encoding="utf-8"))
        print(f"[import-token] Parsed {len(parsed)} entries from {f.name}")
        all_tl.update(parsed)

    items = json.loads(ALL_JSON.read_text(encoding="utf-8"))
    updated = 0
    missing = []
    for item in items:
        g = int(item["g"])
        if g in all_tl and all_tl[g] != "":
            item["en"] = all_tl[g]
            updated += 1
        elif not item.get("en"):
            missing.append(g)

    write_all_json(items)
    print(f"[import-token] Updated {updated} entries in {ALL_JSON.name} ({len(items) - len(missing)}/{len(items)} filled).")
    if missing:
        print(f"[import-token] Still empty ({len(missing)}): {compress_ranges(missing)}")

def do_split_normal(file_args: list[str]):
    files = resolve_files(file_args, ALL_JSON)
    mapping = build_global_mapping()
    g_to_ref = {m["g"]: (m["json_file"], m["id"]) for m in mapping}

    by_file: dict[str, dict[int, str]] = {}
    matched = 0
    for f in files:
        raw_text = strip_fences(f.read_text(encoding="utf-8"))
        arr = json.loads(raw_text)
        if isinstance(arr, dict) and "entries" in arr:
            arr = arr["entries"]
        for item in arr:
            if "g" in item and int(item["g"]) in g_to_ref:
                jf, eid = g_to_ref[int(item["g"])]
            else:
                jf = Path(item["f"]).stem + ".json"
                eid = int(item["id"])
            by_file.setdefault(jf, {})[eid] = str(item.get("en", ""))
            matched += 1

    updated_files = 0
    for jf, reps in by_file.items():
        jpath = JSON_DIR / jf
        jdata = json.loads(jpath.read_text(encoding="utf-8"))
        for e in jdata["entries"]:
            if e["id"] in reps:
                e["en"] = reps[e["id"]]
        jpath.write_text(json.dumps(jdata, ensure_ascii=False, indent=2), encoding="utf-8")
        updated_files += 1
    print(f"[split-normal] Updated {matched} entries across {updated_files} JSON files from {[p.name for p in files]}.")

def do_split_token(file_args: list[str]):
    files = resolve_files(file_args, DEFAULT_TOKEN_OUT)
    mapping = build_global_mapping()

    all_tl: dict[int, str] = {}
    for f in files:
        parsed = parse_token_or_any_json(f.read_text(encoding="utf-8"))
        print(f"[split-token] Parsed {len(parsed)} entries from {f.name}")
        all_tl.update(parsed)

    by_file: dict[str, dict[int, str]] = {}
    missing = []
    for m in mapping:
        g = m["g"]
        if g in all_tl and all_tl[g] != "":
            by_file.setdefault(m["json_file"], {})[m["id"]] = all_tl[g]
        else:
            missing.append(g)

    updated_files = applied = 0
    for jf, reps in by_file.items():
        jpath = JSON_DIR / jf
        jdata = json.loads(jpath.read_text(encoding="utf-8"))
        for e in jdata["entries"]:
            if e["id"] in reps:
                e["en"] = reps[e["id"]]
                applied += 1
        jpath.write_text(json.dumps(jdata, ensure_ascii=False, indent=2), encoding="utf-8")
        updated_files += 1

    print(f"[split-token] Applied {applied}/{len(mapping)} translations across {updated_files} JSON files.")
    if missing:
        print(f"[split-token] Missing {len(missing)} entries. Ranges: {compress_ranges(missing)}")

def run_qc_records(records: list[dict], source_label: str):
    missing_g = []
    overflows = []
    line4_icon = []
    choice_issues = []
    token_issues = []
    sjis_issues = []
    jp_remnants = []

    jp_char_re = re.compile(r"[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FFF]")

    for r in records:
        g = r["g"]
        loc = f"g={g} ({r['file']} id={r['id']})"
        op = r["op"]
        jp = r["jp"]
        en = r["en"]

        if not en.strip():
            missing_g.append(g)
            continue

        san = sanitize_sjis(en)
        bad_chars = []
        for ch in san:
            try:
                ch.encode("cp932")
            except UnicodeEncodeError:
                bad_chars.append(ch)
        if bad_chars:
            sjis_issues.append(f"{loc}: non-Shift-JIS chars {''.join(sorted(set(bad_chars)))!r}")

        for tok in set(re.findall(r"%[A-Za-z0-9]", jp)):
            if san.count(tok) != jp.count(tok):
                token_issues.append(f"{loc}: token {tok} count jp={jp.count(tok)} en={san.count(tok)}")

        if jp_char_re.search(san):
            jp_remnants.append(f"{loc}: {san.splitlines()[0][:50]!r}")

        formatted = format_for_engine(en, jp, op)
        lines = formatted.rstrip("\n").split("\n")

        if op in ("0x0080", "0x0084"):
            if len(lines) > 4:
                overflows.append(f"{loc}: {len(lines)} lines (>4)\n    " + "\n    ".join(lines))
            elif len(lines) == 4 and str_cols(lines[3]) > LINE4_ICON_SAFE_COLS:
                line4_icon.append(f"{loc}: line 4 is {str_cols(lines[3])} cols (> {LINE4_ICON_SAFE_COLS} book icon)")
        elif op == "0x0082":
            jp_lines = jp.rstrip("\n").split("\n")
            if len(lines) != len(jp_lines):
                choice_issues.append(f"{loc}: choice line count jp={len(jp_lines)} en={len(lines)}")
            for ci, cl in enumerate(lines, 1):
                if str_cols(cl) > MAX_COLS:
                    choice_issues.append(f"{loc}: choice #{ci} is {str_cols(cl)} cols (>{MAX_COLS})")

    report = [
        f"QC Report for: {source_label}",
        f"Total entries: {len(records)} | Translated: {len(records) - len(missing_g)} | Empty: {len(missing_g)}",
        f"Missing g ranges: {compress_ranges(missing_g)}",
        f"Hard >4-line overflows: {len(overflows)}",
        f"Choice issues (0x0082): {len(choice_issues)}",
        f"Token mismatches (%n/%s): {len(token_issues)}",
        f"Non-Shift-JIS chars: {len(sjis_issues)}",
        f"Line 4 >{LINE4_ICON_SAFE_COLS} cols (book icon proximity): {len(line4_icon)}",
        f"Untranslated JP chars remaining in en: {len(jp_remnants)}",
        "",
    ]
    for title, lst in [
        ("=== HARD >4-LINE OVERFLOWS ===", overflows),
        ("=== CHOICE ISSUES ===", choice_issues),
        ("=== TOKEN MISMATCHES ===", token_issues),
        ("=== NON-SHIFT-JIS CHARS ===", sjis_issues),
        ("=== LINE 4 BOOK ICON WARNINGS ===", line4_icon),
        ("=== JAPANESE CHARS IN EN ===", jp_remnants),
    ]:
        if lst:
            report.append(title)
            report.extend(lst)
            report.append("")

    QC_REPORT.write_text("\n".join(report), encoding="utf-8")
    for line in report[:9]:
        print("[qc]", line)
    print(f"[qc] Full report written to {QC_REPORT}")

def do_qc(standalone_files: list[str]):
    if standalone_files:
        mapping = build_global_mapping()
        merged_en: dict[int, str] = {}
        for f in resolve_files(standalone_files, DEFAULT_TOKEN_OUT):
            merged_en.update(parse_token_or_any_json(f.read_text(encoding="utf-8")))
        records = [
            {"g": m["g"], "file": m["json_file"], "id": m["id"], "op": m["op"], "jp": m["jp"], "en": merged_en.get(m["g"], "")}
            for m in mapping
        ]
        run_qc_records(records, ", ".join(standalone_files))
    else:
        records = []
        g = 0
        for jpath in sorted(JSON_DIR.glob("*.json")):
            jdata = json.loads(jpath.read_text(encoding="utf-8"))
            for e in jdata["entries"]:
                records.append({"g": g, "file": jpath.name, "id": e["id"], "op": e["op"], "jp": e["jp"], "en": e.get("en", "")})
                g += 1
        run_qc_records(records, str(JSON_DIR))

def do_build():
    if not PAK_ORIG.exists():
        shutil.copy2(PAK_PATH, PAK_ORIG)
        print("[build] Backed up Script.pak -> Script.pak.orig")
    wps_map = {}
    mod_count = 0
    for p in sorted(SCRIPT_DIR.glob("*.Wps")):
        raw = p.read_bytes()
        jpath = JSON_DIR / f"{p.stem}.json"
        if jpath.exists():
            jdata = json.loads(jpath.read_text(encoding="utf-8"))
            reps = {e["id"]: e["en"] for e in jdata["entries"] if e.get("en")}
            if reps:
                mod_count += 1
                wps_map[p.name] = build_wps(parse_wps(raw), reps)
                continue
        wps_map[p.name] = raw
    pack_script_pak(wps_map, PAK_PATH)
    print(f"[build] Packed Script.pak ({mod_count} modified scripts, {len(wps_map)} total).")

def main():
    ap = argparse.ArgumentParser(description="Angelic Serenade .Wps / Script.pak MTL Tool (tar-style flags)")
    ap.add_argument("-T", "--test", action="store_true", help="Verify 145/145 .Wps roundtrip & CRC16")
    ap.add_argument("-x", "--extract", action="store_true", help="Extract .Wps -> tl_json/*.json")
    ap.add_argument("-g", "--gather", action="store_true", help="Gather tl_json/*.json -> ALL_SCRIPTS.json")
    ap.add_argument("-i", "--import-token", action="store_true", help="Import token-optimized output -> ALL_SCRIPTS.json")
    ap.add_argument("-s", "--split", action="store_true", help="Split normal ALL_SCRIPTS.json -> tl_json/*.json")
    ap.add_argument("-t", "--split-token", action="store_true", help="Split token-optimized output -> tl_json/*.json")
    ap.add_argument("-q", "--qc", action="store_true", help="Run QC check without packing (writes qc_report.txt)")
    ap.add_argument("-b", "--build", action="store_true", help="Build .Wps scripts & pack Script.pak")
    ap.add_argument("--force", action="store_true", help="Overwrite existing tl_json/*.json on -x")
    ap.add_argument("files", nargs="*", help="Input JSON file(s) for -i, -s, -t, or standalone -q")
    args = ap.parse_args()

    if not any([args.test, args.extract, args.gather, args.import_token, args.split, args.split_token, args.qc, args.build]):
        ap.print_help()
        return

    if args.test:
        do_test()
    if args.extract:
        do_extract(force=args.force)
    if args.gather:
        do_gather()
    if args.import_token:
        do_import_token(args.files)
    if args.split and args.split_token:
        ap.error("Use either -s (normal JSON) or -t (token-optimized JSON), not both at once.")
    if args.split:
        do_split_normal([] if args.import_token else args.files)
    if args.split_token:
        do_split_token(args.files)
    if args.qc:
        if args.import_token and not args.split and not args.split_token:
            do_qc([str(ALL_JSON)])
        elif args.split or args.split_token:
            do_qc([])
        else:
            do_qc(args.files)
    if args.build:
        do_build()

if __name__ == "__main__":
    main()