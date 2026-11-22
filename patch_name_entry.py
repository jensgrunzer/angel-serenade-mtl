import shutil
import struct
from pathlib import Path

exe_path = Path(r"C:\Games\KOGADO\AS\AS.exe")
bak_path = Path(r"C:\Games\KOGADO\AS\AS.exe.orig")

if not bak_path.exists():
    shutil.copy2(exe_path, bak_path)
    print("Backed up AS.exe -> AS.exe.orig")

data = bytearray(bak_path.read_bytes())

def check_and_patch(off: int, expected: bytes, replacement: bytes, desc: str):
    actual = bytes(data[off : off + len(expected)])
    assert actual == expected, f"[{desc}] mismatch at 0x{off:X}: got {actual.hex(' ')}, expected {expected.hex(' ')}"
    data[off : off + len(replacement)] = replacement
    print(f"Patched {desc} at 0x{off:X}")

# 1. Bypass IsIMEOpen
check_and_patch(0x2A006, b"\x0F\x84\x90\x02\x00\x00", b"\x90" * 6, "allow OK without IME")
check_and_patch(0x2A0FF, b"\x84\xC0\x75\x73", b"\x84\xC0\xEB\x73", "skip 'use Japanese IME' prompt")
check_and_patch(0x2A499, b"\x84\xC0\x75\x20", b"\x84\xC0\xEB\x20", "allow half-width chars")
check_and_patch(0x2AF50, b"\x84\xC0\x74\x49", b"\x84\xC0\xEB\x49", "allow OK click even if IME open")

# 2. Build kb handler in .text slack space (0x122340, VA 0x00522D40)
CAVE_OFF = 0x122340
CAVE_VA = 0x00522D40
MAX_CAVE_SIZE = 0x122400 - CAVE_OFF
assert all(b in (0x00, 0x90, 0xCC) for b in data[CAVE_OFF:0x122400]), "Slack space not empty!"

VA_GETKEYSTATE   = 0x00522A00
VA_MAPVK         = 0x00522B1A
VA_STR_CTOR      = 0x004F27D0
VA_STR_DTOR      = 0x004F28A0
VA_INSERT_CURSOR = 0x0042A538
VA_ORIG_FLOW     = 0x0042B691  # 0x2AC91 (navigation/IME flow)
VA_CLEAN_RET     = 0x0042B793  # 0x2AD93 (DialogPanelKeyDown epilogue)

class Asm:
    def __init__(self, base_va: int):
        self.base_va = base_va
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []

    def cur_va(self):
        return self.base_va + len(self.buf)

    def label(self, name: str):
        self.labels[name] = self.cur_va()

    def emit(self, b: bytes):
        self.buf += b

    def rel8(self, opcode: int, lbl: str):
        self.buf.append(opcode)
        self.fixups.append((len(self.buf), 1, lbl, True))
        self.buf.append(0)

    def call_va(self, va: int):
        self.buf.append(0xE8)
        self.fixups.append((len(self.buf), 4, va, False))
        self.buf += b"\x00\x00\x00\x00"

    def jmp_va(self, va: int):
        self.buf.append(0xE9)
        self.fixups.append((len(self.buf), 4, va, False))
        self.buf += b"\x00\x00\x00\x00"

    def link(self) -> bytes:
        for pos, sz, target, is_lbl in self.fixups:
            dst = self.labels[target] if is_lbl else target
            src_next = self.base_va + pos + sz
            rel = dst - src_next
            if sz == 1:
                assert -128 <= rel <= 127, f"Short jump out of range: {rel}"
                self.buf[pos] = rel & 0xFF
            else:
                struct.pack_into("<i", self.buf, pos, rel)
        return bytes(self.buf)

a = Asm(CAVE_VA)
# Trampoline at top so all short jumps to 'orig' stay within -128..0 bytes
a.label("orig")
a.jmp_va(VA_ORIG_FLOW)

a.label("entry")
# On entry from 0x2AC30: EBX = this, ESI = WORD *Key
a.emit(b"\x0F\xB7\x06")              # movzx eax, word ptr [esi]
a.emit(b"\x83\xF8\x20")              # cmp eax, 0x20
a.rel8(0x72, "orig")                 # jb orig (Backspace, Esc, Enter, etc.)
a.emit(b"\x83\xF8\x25")              # cmp eax, VK_LEFT
a.rel8(0x74, "orig")
a.emit(b"\x83\xF8\x27")              # cmp eax, VK_RIGHT
a.rel8(0x74, "orig")
a.emit(b"\x83\xF8\x2E")              # cmp eax, VK_DELETE
a.rel8(0x74, "orig")

# Skip if Ctrl (0x11) or Alt (0x12)
a.emit(b"\x6A\x11")                  # push VK_CONTROL
a.call_va(VA_GETKEYSTATE)
a.emit(b"\xF6\xC4\x80")              # test ah, 0x80
a.rel8(0x75, "orig")
a.emit(b"\x6A\x12")                  # push VK_MENU
a.call_va(VA_GETKEYSTATE)
a.emit(b"\xF6\xC4\x80")              # test ah, 0x80
a.rel8(0x75, "orig")

# MapVirtualKeyA(vk, MAPVK_VK_TO_CHAR=2)
a.emit(b"\x0F\xB7\x06")              # movzx eax, word ptr [esi]
a.emit(b"\x6A\x02\x50")              # push 2; push eax
a.call_va(VA_MAPVK)
a.emit(b"\x25\xFF\x00\x00\x00")      # and eax, 0xFF
a.emit(b"\x3C\x20")                  # cmp al, 0x20
a.rel8(0x72, "orig")
a.emit(b"\x3C\x7E")                  # cmp al, 0x7E
a.rel8(0x77, "orig")

# Handle Shift / CapsLock for A-Z
a.emit(b"\x3C\x41")                  # cmp al, 'A'
a.rel8(0x72, "make_str")
a.emit(b"\x3C\x5A")                  # cmp al, 'Z'
a.rel8(0x77, "make_str")
a.emit(b"\x50")                      # push eax (save letter)
a.emit(b"\x6A\x10")                  # push VK_SHIFT
a.call_va(VA_GETKEYSTATE)
a.emit(b"\xC1\xE8\x0F\x83\xE0\x01")  # shr eax, 15; and eax, 1
a.emit(b"\x50")                      # push eax (shift_bit)
a.emit(b"\x6A\x14")                  # push VK_CAPITAL
a.call_va(VA_GETKEYSTATE)
a.emit(b"\x83\xE0\x01")              # and eax, 1
a.emit(b"\x5A\x31\xD0\x5A")          # pop edx; xor eax, edx; pop edx
a.emit(b"\x84\xC0\x89\xD0")          # test al, al; mov eax, edx
a.rel8(0x75, "make_str")             # jnz make_str (keep uppercase)
a.emit(b"\x04\x20")                  # add al, 0x20 (lowercase)

a.label("make_str")
a.emit(b"\x6A\x00\x88\x04\x24")      # push 0; mov [esp], al  (cstr)
a.emit(b"\x6A\x00")                  # push 0                 (local AnsiString)
a.emit(b"\x89\xE2\x83\xC2\x04")      # mov edx, esp; add edx, 4
a.emit(b"\x89\xE0")                  # mov eax, esp
a.call_va(VA_STR_CTOR)
a.emit(b"\x8B\x04\x24\x50\x53")      # mov eax, [esp]; push eax; push ebx
a.call_va(VA_INSERT_CURSOR)
a.emit(b"\x83\xC4\x08")              # add esp, 8
a.emit(b"\x89\xE0\xBA\x02\x00\x00\x00")  # mov eax, esp; mov edx, 2
a.call_va(VA_STR_DTOR)
a.emit(b"\x83\xC4\x08")              # add esp, 8
a.jmp_va(VA_CLEAN_RET)

cave_bytes = a.link()
assert len(cave_bytes) <= MAX_CAVE_SIZE, f"Cave too big: {len(cave_bytes)} > {MAX_CAVE_SIZE}"
data[CAVE_OFF : CAVE_OFF + len(cave_bytes)] = cave_bytes
print(f"Wrote Latin key handler ({len(cave_bytes)}/{MAX_CAVE_SIZE} bytes) at 0x{CAVE_OFF:X}")

# 3. Hook DialogPanelKeyDown at 0x2AC30 (VA 0x0042B630)
entry_va = a.labels["entry"]
hook_rel = entry_va - (0x0042B631 + 5)
check_and_patch(0x2AC31, b"\x66\x8B\x06\x66\x83", b"\xE9" + struct.pack("<i", hook_rel), "hook DialogPanelKeyDown")

exe_path.write_bytes(data)
print("Successfull")
