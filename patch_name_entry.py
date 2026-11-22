from pathlib import Path
import shutil

exe_path = Path(r"C:\Games\KOGADO\AS\AS.exe")
bak_path = Path(r"C:\Games\KOGADO\AS\AS.exe.orig")

if not bak_path.exists():
    shutil.copy2(exe_path, bak_path)
    print("Backed up AS.exe -> AS.exe.orig")

data = bytearray(bak_path.read_bytes())
sig = data[0x2A499:0x2A49D]
assert sig == b"\x84\xC0\x75\x20", f"Unexpected bytes at 0x2A499: {sig.hex(' ')}"

data[0x2A49B] = 0xEB  # JNZ -> JMP (skip half-width rejection)
exe_path.write_bytes(data)
print("Patched AS.exe Name Entry check successfully.")