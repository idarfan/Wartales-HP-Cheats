#!/usr/bin/env python3
"""
診斷工具：解壓存檔，搜尋 MaxHealth 相關 bytes，印出周圍 context
用法：python analyze_save.py <save.dat>
"""
import sys, hashlib, re, struct, zlib
from pathlib import Path

CIPHER_MAGIC = 0xCAFECAFE

def cypher(buf: bytearray):
    for i in range(len(buf) // 4):
        p = i * 4
        w = struct.unpack_from('<I', buf, p)[0]
        struct.pack_into('<I', buf, p, (w ^ p ^ CIPHER_MAGIC) & 0xFFFFFFFF)

def unpack(raw):
    magic, pos, chunks = raw[:4], 4, []
    while pos + 4 <= len(raw):
        n = struct.unpack_from('<i', raw, pos)[0]; pos += 4
        chunks.append(bytearray(raw[pos:pos+n])); pos += n
    enc = chunks[0][:1] != b'o'
    if enc:
        for c in chunks: cypher(c)
    body_raw = bytes(chunks[2])
    comp = body_raw[:1] == b'\x78'
    return zlib.decompress(body_raw) if comp else body_raw

def hexdump(data, offset=0, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append(f"  {offset+i:08x}  {hex_part:<{width*3}}  {asc_part}")
    return '\n'.join(lines)

body = unpack(Path(sys.argv[1]).read_bytes())
print(f"Body size: {len(body):,} bytes\n")

# 搜尋 "MaxHealth" 字串（不管 hxbit encoding）
mh = b'MaxHealth'
positions = [m.start() for m in re.finditer(mh, body)]
print(f"'MaxHealth' 出現次數: {len(positions)}")
for pos in positions[:10]:
    print(f"\n  offset {pos:#08x}  前20後20 bytes:")
    start = max(0, pos - 20)
    end   = min(len(body), pos + len(mh) + 20)
    print(hexdump(body[start:end], start))
    # 印出前一個 byte（bitmask）
    if pos > 0:
        print(f"  前一 byte: 0x{body[pos-1]:02x}")
    if pos > 1:
        print(f"  前二 byte: 0x{body[pos-2]:02x}")

# 也搜尋 "Strength" 確認 upgrades 格式
st = b'Strength'
positions2 = [m.start() for m in re.finditer(st, body)]
print(f"\n'Strength' 出現次數: {len(positions2)}")
for pos in positions2[:3]:
    print(f"\n  offset {pos:#08x}  前10後10:")
    start = max(0, pos - 10)
    end   = min(len(body), pos + len(st) + 10)
    print(hexdump(body[start:end], start))
    if pos > 0: print(f"  前一 byte: 0x{body[pos-1]:02x}")

