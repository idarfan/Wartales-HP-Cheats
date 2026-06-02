#!/usr/bin/env python3
"""Wartales Save Editor v5 — GUI for Windows 11, Python 3.x (no extra packages)"""

import argparse, hashlib, re, struct, sys, shutil, zlib
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox

# ═══════════════════════════════════════════════════════════════════
#  核心編解碼（完整保留 bitumin gist 原版邏輯，一字不改）
# ═══════════════════════════════════════════════════════════════════
CIPHER_MAGIC = 0xCAFECAFE
RESOURCE_KEY = 0x5b62db6d
RESOURCE_MUL = 0x1F
RESOURCE_MAX = (0xFFFFFFFF // RESOURCE_MUL)

RESOURCES = [
    ('Gold',        'gold'),
    ('Influence',   'influence'),
    ('Happiness',   'happiness'),
    ('ActionPoint', 'valour'),
    ('Discovery',   'discovery'),
    ('Knowledge',   'knowledge'),
]
RESOURCE_LABEL = {
    'Gold':'金幣 (Krowns)', 'Influence':'影響力 (Influence)',
    'Happiness':'幸福度 (Happiness)', 'ActionPoint':'英勇點 (Valour)',
    'Discovery':'探索度 (Discovery)', 'Knowledge':'知識 (Knowledge)',
}
RES_ICONS = {
    'Gold':'🪙', 'Influence':'⭐', 'Happiness':'😊',
    'ActionPoint':'⚡', 'Discovery':'🗺', 'Knowledge':'📖',
}

def cypher(buf: bytearray):
    n = len(buf) // 4
    for i in range(n):
        p = i * 4
        w = struct.unpack_from('<I', buf, p)[0]
        struct.pack_into('<I', buf, p, (w ^ p ^ CIPHER_MAGIC) & 0xFFFFFFFF)

def make_signature(data: bytes) -> bytes:
    h = bytearray(hashlib.sha1(data).digest())
    for k in (0, 4, 8, 12):
        a = struct.unpack_from('<I', h, k)[0]
        b = struct.unpack_from('<I', h, k + 8)[0] if k + 12 <= len(h) else 0
        struct.pack_into('<I', h, k, (a ^ b) & 0xFFFFFFFF)
    return bytes(h)

def encode_resource(v: int) -> int:
    return ((v * RESOURCE_MUL) ^ RESOURCE_KEY) & 0xFFFFFFFF

def decode_resource(enc: int):
    x = enc ^ RESOURCE_KEY
    return x // RESOURCE_MUL if x % RESOURCE_MUL == 0 else None

def unpack(raw: bytes):
    if raw[:3] != b'WTA':
        raise ValueError(f"不是 Wartales 存檔 (magic={raw[:4]!r})")
    magic = raw[:4]
    pos, chunks = 4, []
    while pos + 4 <= len(raw):
        n = struct.unpack_from('<i', raw, pos)[0]; pos += 4
        if n < 0 or pos + n > len(raw):
            raise ValueError(f"存檔損壞：chunk 長度異常 {n}")
        chunks.append(bytearray(raw[pos:pos+n])); pos += n
    if len(chunks) < 3:
        raise ValueError(f"存檔格式錯誤：只有 {len(chunks)} 個 chunk")
    encrypted = chunks[0][:1] != b'o'
    if encrypted:
        for c in chunks: cypher(c)
    header   = bytes(chunks[0])
    body_raw = bytes(chunks[2])
    compressed = body_raw[:1] == b'\x78'
    body = zlib.decompress(body_raw) if compressed else body_raw
    return magic, header, bytes(chunks[1]), body, encrypted, compressed

def pack(magic, header, body, encrypt, compress) -> bytes:
    sig      = make_signature(body)
    body_out = zlib.compress(body) if compress else body
    chunks   = [bytearray(header), bytearray(sig), bytearray(body_out)]
    if encrypt:
        for c in chunks: cypher(c)
    out = bytearray(magic)
    for c in chunks:
        out += struct.pack('<i', len(c)); out += c
    return bytes(out)

def find_resource(body: bytes, name: str):
    """
    完整保留 bitumin gist 原版。
    回傳 (enc_off, cache_off, cache_width, cache_val, enc_raw, decoded, enc_form)
    """
    pat = bytes([0x0c, 0x5c, 0x01, len(name) + 1]) + name.encode()
    m = re.search(re.escape(pat), body)
    if not m: return None
    name_idx = m.start()

    # xor5/c5
    five_cache_off = name_idx - 10
    five_enc_off   = name_idx - 15
    if (five_enc_off >= 0
            and body[five_enc_off] == 0x80
            and body[five_cache_off] == 0x80):
        cache_val = struct.unpack_from('<i', body, five_cache_off + 1)[0]
        enc_raw   = struct.unpack_from('<I', body, five_enc_off + 1)[0]
        return (five_enc_off, five_cache_off, 5, cache_val, enc_raw,
                decode_resource(enc_raw), 'xor5/c5')

    # xor5/c1
    one_cache_off = name_idx - 6
    one_enc_off   = name_idx - 11
    if (one_enc_off >= 0
            and body[one_enc_off] == 0x80
            and body[one_cache_off] < 0x80):
        cache_val = body[one_cache_off]
        enc_raw   = struct.unpack_from('<I', body, one_enc_off + 1)[0]
        return (one_enc_off, one_cache_off, 1, cache_val, enc_raw,
                decode_resource(enc_raw), 'xor5/c1')

    # null/c1
    null_cache_off = name_idx - 6
    null_enc_off   = name_idx - 7
    if (null_enc_off >= 0
            and body[null_enc_off] == 0x00
            and body[null_cache_off] < 0x80):
        cache_val = body[null_cache_off]
        return (null_enc_off, null_cache_off, 1, cache_val, None, None, 'null/c1')

    return None

def patch_resource(body: bytearray, name: str, new_val: int):
    """
    修改資源，自動處理 1B↔5B 跨邊界（in-place splice，不需寫檔）。
    回傳 (old_val, desc_str)；找不到時 raise ValueError。
    """
    info = find_resource(bytes(body), name)
    if info is None:
        raise ValueError(f"找不到資源：{name}")
    enc_off, cache_off, cache_width, cache_val, enc_raw, decoded, enc_form = info

    new_w = 1 if 0 <= new_val < 0x80 else 5

    if new_w == cache_width:
        # 同寬度，直接覆寫
        _write_resource(body, enc_off, cache_off, cache_width, enc_form, new_val)
        return cache_val, f"{cache_val:,} → {new_val:,}"

    # 跨邊界展開 / 縮小（in-place）
    # enc_off 永遠在 cache_off 前面，先展開 cache，enc_off 不移動
    if cache_width == 1 and new_w == 5:
        # 1→5：把 cache 那 1 byte 替換成 5 bytes
        body[cache_off:cache_off + 1] = b'\x80' + struct.pack('<i', new_val)
        # enc_off 位置不變（在 cache_off 前面）
        body[enc_off:enc_off + 5] = b'\x80' + struct.pack('<I', encode_resource(new_val))
    elif cache_width == 5 and new_w == 1:
        body[cache_off:cache_off + 5] = bytes([new_val])
        body[enc_off:enc_off + 5] = b'\x80' + struct.pack('<I', encode_resource(new_val))

    return cache_val, f"{cache_val:,} → {new_val:,}（自動展開 {cache_width}B→{new_w}B）"

def _write_resource(body, enc_off, cache_off, cache_width, enc_form, val):
    if enc_form == 'null/c1':
        body[cache_off] = val
    else:
        body[enc_off:enc_off + 5] = b'\x80' + struct.pack('<I', encode_resource(val))
        if cache_width == 5:
            body[cache_off:cache_off + 5] = b'\x80' + struct.pack('<i', val)
        else:
            body[cache_off] = val

# ═══════════════════════════════════════════════════════════════════
#  MaxHealth 直接搜尋（字串 pattern，不用 UID marker）
# ═══════════════════════════════════════════════════════════════════
def _varint_r(b, o):
    v = b[o]
    if v < 0x80: return v, o + 1
    if v == 0x80: return struct.unpack_from('<i', b, o + 1)[0], o + 5
    raise ValueError(f"bad varint 0x{v:02x} @{o:#x}")

def _varint_w(v):
    if 0 <= v < 0x80: return bytes([v])
    return b'\x80' + struct.pack('<i', v)

def _hxstr(s: str) -> bytes:
    """hxbit string encoding"""
    e = s.encode()
    n = len(e) + 1
    return (bytes([n]) if n < 0x80 else b'\x80' + struct.pack('<i', n)) + e

# "MaxHealth" hxbit 字串 pattern
MH_STR = _hxstr('MaxHealth')   # 0x0a 4d 61 78 48 65 61 6c 74 68

def scan_maxhealth(body: bytes):
    """
    掃描所有 MaxHealth upgrades entry。
    entry 結構：[bitmask varint = 0x02] [MH_STR] [base_bool 0/1] [value varint]
    只要前一個 byte 是 0x02 即視為合法 entry。
    回傳 list of dict。
    """
    results = []
    for m in re.finditer(re.escape(MH_STR), body):
        str_start = m.start()
        # bitmask byte 在字串前一格
        bm_off = str_start - 1
        if bm_off < 0: continue
        bm = body[bm_off]
        # bitmask+1 應為 2（表示 'a' field present），也接受 0x82（5-byte varint 形式的 2）
        if bm not in (0x02,): continue
        # bool byte
        bool_off = str_start + len(MH_STR)
        if bool_off >= len(body): continue
        base = body[bool_off]
        if base not in (0, 1): continue
        # value varint
        val_off = bool_off + 1
        if val_off >= len(body): continue
        try:
            val, _ = _varint_r(body, val_off)
        except Exception:
            continue
        if not -32768 <= val <= 32767: continue
        val_w = 1 if 0 <= val < 0x80 else 5
        results.append({
            'bm_off':   bm_off,
            'str_start': str_start,
            'bool_off': bool_off,
            'val_off':  val_off,
            'val':      val,
            'val_w':    val_w,
        })
    return results

def nearby_name(body: bytes, str_start: int, window: int = 1500) -> str:
    """在 MaxHealth 字串前 window bytes 內找最近的疑似角色名字"""
    SKIP = {
        'Strength','Dexterity','Constitution','Willpower','Movement',
        'CritHitPercent','MaxHealth','Armor','Guard','VisionRange','Morale',
        'Transport','DamageBonusPercent','DamageReducePercent','Pikeman',
        'Warrior','Brute','Swordman','Ranger','Archer','Spearman',
        'Tinkerer','Bard','Alchemist','Cook','Miner','Blacksmith',
        'Thief','Herbalist','Peddler','BeastMaster','Prisoner',
        'true','false','null',
    }
    start = max(0, str_start - window)
    chunk = body[start:str_start]
    # 從後往前掃
    i = len(chunk) - 2
    while i >= 1:
        p1 = chunk[i]
        if 2 <= p1 <= 21:
            nb = chunk[i+1:i+p1]
            if len(nb) == p1 - 1 and all(0x20 <= c < 0x7f for c in nb):
                s = nb.decode()
                if len(s) >= 3 and s not in SKIP and s[0].isupper():
                    return s
        i -= 1
    return "?"

def set_all_maxhealth(body: bytearray, target: int) -> int:
    """逐一修改所有 MaxHealth 條目，處理 varint 寬度變化。"""
    count = 0
    while True:
        entries = scan_maxhealth(bytes(body))
        changed = False
        for e in entries:
            if e['val'] == target:
                continue
            old_w = e['val_w']
            new_w = 1 if 0 <= target < 0x80 else 5
            body[e['val_off']: e['val_off'] + old_w] = _varint_w(target)
            count += 1
            changed = True
            break   # body 變了，重新掃描
        if not changed:
            break
    return count

# ═══════════════════════════════════════════════════════════════════
#  GUI
# ═══════════════════════════════════════════════════════════════════
BG   = "#1e1e2e"; BG2 = "#313244"; BG3 = "#181825"
FG   = "#cdd6f4"; ACC = "#89b4fa"; GRN = "#a6e3a1"
RED  = "#f38ba8"; YEL = "#f9e2af"; GRAY= "#6c7086"; LINE= "#45475a"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wartales Save Editor  v5")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.save_path = self.magic = self.header = None
        self.body_ba = None
        self.enc = self.comp = False
        self.vars = {k: tk.StringVar() for k, _ in RESOURCES}
        self._build()
        self._enable(False)

    # ─── UI 建立 ────────────────────────────────────────────────────
    def _build(self):
        # 標題
        h = tk.Frame(self, bg=BG3, pady=12); h.pack(fill="x")
        tk.Label(h, text="⚔  Wartales Save Editor",
                 font=("Segoe UI",15,"bold"), bg=BG3, fg=ACC).pack()
        tk.Label(h, text="修改資源 · 最大化角色血量",
                 font=("Segoe UI",9), bg=BG3, fg=GRAY).pack()

        # 開檔列
        r0 = tk.Frame(self, bg=BG, pady=8); r0.pack(fill="x", padx=14)
        tk.Label(r0, text="存檔：", bg=BG, fg=FG,
                 font=("Segoe UI",9)).pack(side="left")
        self.path_lbl = tk.Label(r0, text="尚未選擇", bg=BG, fg=GRAY,
                                  font=("Segoe UI",9), width=38, anchor="w")
        self.path_lbl.pack(side="left", padx=4)
        self._mkbtn(r0, "📂 開啟", self._open, ACC).pack(side="right")
        tk.Frame(self, bg=LINE, height=1).pack(fill="x", padx=14)

        # 分頁
        nb = tk.Frame(self, bg=BG); nb.pack(fill="both", expand=True, padx=14, pady=8)
        self.tab_btns = []; self.tabs = []
        tab_bar = tk.Frame(nb, bg=BG); tab_bar.pack(fill="x")
        content = tk.Frame(nb, bg=BG2, highlightthickness=1, highlightbackground=LINE)
        content.pack(fill="both", expand=True)
        for i, lbl in enumerate(["📦 資源修改", "❤️ 血量最大化"]):
            f = tk.Frame(content, bg=BG2); self.tabs.append(f)
            b = tk.Button(tab_bar, text=lbl,
                          bg=BG2 if i==0 else BG, fg=FG,
                          font=("Segoe UI",9,"bold"), relief="flat",
                          padx=12, pady=6, cursor="hand2", bd=0,
                          activebackground=BG2, activeforeground=ACC,
                          command=lambda i=i: self._tab(i))
            b.pack(side="left"); self.tab_btns.append(b)
        self._build_res(self.tabs[0])
        self._build_hp(self.tabs[1])
        self._tab(0)

        tk.Frame(self, bg=LINE, height=1).pack(fill="x", padx=14)
        self.status_v = tk.StringVar(value="請先開啟存檔")
        self.status_l = tk.Label(self, textvariable=self.status_v,
                                  bg=BG, fg=GRAY, font=("Segoe UI",9), anchor="w")
        self.status_l.pack(fill="x", padx=16, pady=4)

    def _tab(self, idx):
        for f in self.tabs: f.pack_forget()
        self.tabs[idx].pack(fill="both", expand=True, padx=8, pady=8)
        for i, b in enumerate(self.tab_btns):
            b.config(bg=BG2 if i==idx else BG, fg=ACC if i==idx else FG)

    def _build_res(self, parent):
        for internal, _ in RESOURCES:
            label = RESOURCE_LABEL[internal]
            icon  = RES_ICONS[internal]
            row = tk.Frame(parent, bg=BG2); row.pack(fill="x", pady=3)
            tk.Label(row, text=f"{icon}  {label}", bg=BG2, fg=FG,
                     font=("Segoe UI",10), width=24, anchor="w").pack(side="left", padx=6)
            cur = tk.Label(row, text="—", bg=BG, fg=GRAY,
                            font=("Consolas",10), width=14, anchor="e", padx=6)
            cur.pack(side="left", padx=4)
            setattr(self, f"cur_{internal}", cur)
            ent = tk.Entry(row, textvariable=self.vars[internal],
                           bg=BG, fg=FG, insertbackground=FG,
                           font=("Consolas",10), width=14, relief="flat",
                           highlightthickness=1, highlightbackground=LINE,
                           highlightcolor=ACC)
            ent.pack(side="left", ipady=4)
            setattr(self, f"ent_{internal}", ent)
            for val, txt in [(99999,"10萬"),(999999,"100萬"),(9999999,"1000萬")]:
                tk.Button(row, text=txt, bg=LINE, fg=FG,
                          font=("Segoe UI",8), relief="flat",
                          padx=5, pady=2, cursor="hand2",
                          activebackground=ACC, activeforeground=BG3,
                          command=lambda v=val, i=internal: self.vars[i].set(str(v))
                         ).pack(side="left", padx=2)
        tk.Frame(parent, bg=LINE, height=1).pack(fill="x", pady=6)
        br = tk.Frame(parent, bg=BG2); br.pack(fill="x")
        self._btn_reload   = self._mkbtn(br, "🔄 重新載入", self._reload, YEL, 12)
        self._btn_reload.pack(side="right", padx=4)
        self._btn_save_res = self._mkbtn(br, "💾 儲存資源", self._save_resources, GRN, 14)
        self._btn_save_res.pack(side="right", padx=4)
        tk.Label(parent, text="✅ 支援任意數值，自動處理編碼格式",
                 bg=BG2, fg=GRN, font=("Segoe UI",8)).pack(anchor="w", padx=4, pady=2)

    def _build_hp(self, parent):
        tk.Label(parent,
                 text="搜尋存檔中所有 MaxHealth 升級條目並修改數值。\n"
                      "請先按【🔍 掃描】確認找到條目後，再按修改。",
                 bg=BG2, fg=FG, font=("Segoe UI",10),
                 justify="left", wraplength=400).pack(anchor="w", padx=8, pady=8)
        row = tk.Frame(parent, bg=BG2); row.pack(fill="x", padx=8, pady=4)
        tk.Label(row, text="MaxHealth 值：", bg=BG2, fg=FG,
                 font=("Segoe UI",10)).pack(side="left")
        self.hp_var = tk.StringVar(value="500")
        self.ent_hp = tk.Entry(row, textvariable=self.hp_var, bg=BG, fg=FG,
                                insertbackground=FG, font=("Consolas",11),
                                width=8, relief="flat",
                                highlightthickness=1, highlightbackground=LINE,
                                highlightcolor=ACC)
        self.ent_hp.pack(side="left", padx=6, ipady=4)
        for val, txt in [(200,"200"),(500,"500"),(999,"999"),(9999,"9999")]:
            tk.Button(row, text=txt, bg=LINE, fg=FG,
                      font=("Segoe UI",9), relief="flat", padx=6, pady=2,
                      cursor="hand2", activebackground=ACC, activeforeground=BG3,
                      command=lambda v=val: self.hp_var.set(str(v))
                     ).pack(side="left", padx=2)

        lf = tk.Frame(parent, bg=BG2); lf.pack(fill="x", padx=8, pady=4)
        tk.Label(lf, text="掃描結果（MaxHealth 條目）：",
                 bg=BG2, fg=GRAY, font=("Segoe UI",8)).pack(anchor="w")
        self.comp_list = tk.Listbox(lf, bg=BG, fg=FG, font=("Consolas",9),
                                     height=7, relief="flat",
                                     highlightthickness=1, highlightbackground=LINE,
                                     selectbackground=ACC, selectforeground=BG3)
        self.comp_list.pack(fill="x")
        self.comp_list.insert("end", "（開啟存檔後按掃描）")

        scan_r = tk.Frame(parent, bg=BG2); scan_r.pack(fill="x", padx=8, pady=4)
        self._btn_scan = self._mkbtn(scan_r, "🔍 掃描", self._scan_hp, ACC, 10)
        self._btn_scan.pack(side="left")
        tk.Label(scan_r, text="← 先掃描確認有條目，再按下方修改",
                 bg=BG2, fg=GRAY, font=("Segoe UI",8)).pack(side="left", padx=8)

        tk.Frame(parent, bg=LINE, height=1).pack(fill="x", pady=4)
        self._btn_hp = self._mkbtn(parent, "❤️  修改所有 MaxHealth", self._set_hp, RED, 22)
        self._btn_hp.pack(pady=6)

    def _mkbtn(self, parent, text, cmd, color, width=10):
        return tk.Button(parent, text=text, command=cmd,
                         bg=color, fg=BG3, font=("Segoe UI",9,"bold"),
                         relief="flat", padx=10, pady=5, cursor="hand2",
                         width=width, activebackground=color, activeforeground=BG3)

    def _enable(self, on: bool):
        st = "normal" if on else "disabled"
        for k, _ in RESOURCES: getattr(self, f"ent_{k}").config(state=st)
        for a in ("_btn_save_res", "_btn_reload", "_btn_hp", "ent_hp", "_btn_scan"):
            getattr(self, a).config(state=st)

    def _st(self, msg, color=None):
        self.status_v.set(msg); self.status_l.config(fg=color or GRAY)

    # ─── 開啟存檔 ───────────────────────────────────────────────────
    def _open(self):
        # 預設開啟當前目錄
        init = str(Path.cwd())
        path = filedialog.askopenfilename(
            title="選擇 Wartales 存檔",
            filetypes=[("Wartales 存檔", "*.dat"), ("所有檔案", "*.*")],
            initialdir=init)
        if path: self._load(Path(path))

    def _load(self, path: Path):
        try:
            magic, header, sig, body, enc, comp = unpack(path.read_bytes())
        except Exception as e:
            messagebox.showerror("載入失敗", str(e)); return
        self.save_path = path
        self.magic, self.header = magic, header
        self.body_ba = bytearray(body)
        self.enc, self.comp = enc, comp
        nm = path.name
        self.path_lbl.config(
            text=("..."+nm[-38:] if len(nm) > 41 else nm), fg=FG)
        self._refresh_res()
        self._enable(True)
        self._scan_hp()
        self._st(f"已載入  加密:{'是' if enc else '否'}  "
                 f"壓縮:{'是' if comp else '否'}  {len(body):,} bytes", ACC)

    def _refresh_res(self):
        for internal, _ in RESOURCES:
            v = None
            info = find_resource(bytes(self.body_ba), internal)
            if info: v = info[3]
            lbl = getattr(self, f"cur_{internal}")
            if v is None:
                lbl.config(text="不存在", fg=GRAY)
                self.vars[internal].set("")
            else:
                lbl.config(text=f"{v:,}", fg=FG)
                self.vars[internal].set(str(v))

    def _reload(self):
        if self.save_path: self._load(self.save_path)

    # ─── 儲存資源 ───────────────────────────────────────────────────
    def _save_resources(self):
        if not self.save_path: return
        patches, errors = {}, []
        for internal, _ in RESOURCES:
            raw = self.vars[internal].get().strip().replace(',','').replace('_','')
            if not raw: continue
            try:   v = int(raw)
            except ValueError:
                errors.append(f"{RESOURCE_LABEL[internal]}：請輸入整數"); continue
            if not 0 <= v <= RESOURCE_MAX:
                errors.append(f"{RESOURCE_LABEL[internal]}：超出範圍 0~{RESOURCE_MAX:,}"); continue
            info = find_resource(bytes(self.body_ba), internal)
            if info and info[3] == v: continue   # 沒變
            patches[internal] = v
        if errors:
            messagebox.showerror("輸入錯誤", "\n".join(errors)); return
        if not patches:
            messagebox.showinfo("提示", "沒有任何修改。"); return
        applied, failed = [], []
        for internal, new_val in patches.items():
            lbl = RESOURCE_LABEL[internal]
            try:
                old_val, desc = patch_resource(self.body_ba, internal, new_val)
                applied.append(f"{lbl}：{desc}")
            except Exception as e:
                failed.append(f"{lbl}：{e}")
        if failed: messagebox.showwarning("部分失敗", "\n".join(failed))
        if applied: self._do_save("資源修改：" + "；".join(applied))

    # ─── 血量掃描 ───────────────────────────────────────────────────
    def _scan_hp(self):
        if not self.body_ba: return
        self.comp_list.delete(0, "end")
        entries = scan_maxhealth(bytes(self.body_ba))
        if not entries:
            self.comp_list.insert("end", "（找不到 MaxHealth 條目）")
            self._st("找不到 MaxHealth 條目（此存檔可能無角色升級資料）", YEL)
            return
        for i, e in enumerate(entries, 1):
            name = nearby_name(bytes(self.body_ba), e['str_start'])
            self.comp_list.insert("end",
                f"  #{i:<2} ~{name:<14} MaxHealth = {e['val']}"
                f"  @{e['val_off']:#08x}")
        self._st(f"掃描到 {len(entries)} 個 MaxHealth 條目", ACC)

    def _set_hp(self):
        if not self.save_path: return
        try:
            target = int(self.hp_var.get().strip())
            if target <= 0: raise ValueError
        except ValueError:
            messagebox.showerror("錯誤", "請輸入正整數"); return
        entries = scan_maxhealth(bytes(self.body_ba))
        if not entries:
            messagebox.showinfo("提示",
                "找不到任何 MaxHealth 條目\n請先按【🔍 掃描】確認"); return
        if not messagebox.askyesno("確認",
            f"找到 {len(entries)} 個 MaxHealth 條目\n"
            f"全部設成 {target}？\n存檔前會自動備份。"):
            return
        try:
            count = set_all_maxhealth(self.body_ba, target)
        except Exception as e:
            messagebox.showerror("失敗", str(e)); return
        self._do_save(f"MaxHealth × {count} 條目 → {target}")
        self._scan_hp()

    # ─── 統一儲存 ───────────────────────────────────────────────────
    def _do_save(self, desc: str):
        try:
            bak = self.save_path.with_suffix(
                f'.bak_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
            shutil.copy2(self.save_path, bak)
            self.save_path.write_bytes(
                pack(self.magic, self.header, bytes(self.body_ba),
                     self.enc, self.comp))
        except Exception as e:
            messagebox.showerror("儲存失敗", str(e)); return
        self._refresh_res()
        self._st(f"✓ {desc}  |  備份：{bak.name}", GRN)
        messagebox.showinfo("完成", f"{desc}\n\n備份：{bak.name}")

if __name__ == "__main__":
    App().mainloop()
