#!/usr/bin/env python3
"""Wartales Trainer v9 — 自動指標學習，重啟後自動恢復"""
import ctypes, sys, struct, threading, re, json, os
import tkinter as tk
from tkinter import messagebox

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        " ".join(f'"{a}"' for a in sys.argv), None, 1)
    sys.exit()

try:
    import pymem, pymem.pattern, pymem.process, pymem.memory
    import pymem.ressources.structure as S
except ImportError:
    import subprocess
    subprocess.run([sys.executable,"-m","pip","install","pymem"], check=True)
    import pymem, pymem.pattern, pymem.process, pymem.memory
    import pymem.ressources.structure as S

# ── 常數 ────────────────────────────────────────────────────────────
RKEY=0x5b62db6d; RMUL=0x1F
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                         "wartales_data.json")

def enc_gold(v): return ((v*RMUL)^RKEY)&0xFFFFFFFF

# ── 記憶體工具 ───────────────────────────────────────────────────────
def rdi(pm,a):
    try: return pm.read_int(a)
    except: return None
def wdi(pm,a,v):
    try: pm.write_int(a,v)
    except: pass
def wdf(pm,a,v):
    try: pm.write_float(a,v)
    except: pass
def wdu(pm,a,v):
    try: pm.write_uint(a,v)
    except: pass
def read8(pm,a):
    try: return struct.unpack('<Q',
            pymem.memory.read_bytes(pm.process_handle,a,8))[0]
    except: return None

def get_module_base(pm,name="Wartales.exe"):
    try: return pymem.process.module_from_name(pm.process_handle,name).lpBaseOfDll
    except: return None

def is_module_addr(pm,addr):
    try:
        mbi=pymem.memory.virtual_query(pm.process_handle,addr)
        return mbi.Type==0x1000000  # MEM_IMAGE
    except: return False

# ── 掃描 ────────────────────────────────────────────────────────────
def scan_value(pm, val_bytes, stop_evt=None, progress_cb=None):
    pattern=re.escape(val_bytes); found=[]; addr=0
    limit=0x7FFFFFFF0000; n=0
    allowed={S.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
             S.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READONLY}
    while addr<limit:
        if stop_evt and stop_evt.is_set(): break
        try: mbi=pymem.memory.virtual_query(pm.process_handle,addr)
        except: break
        next_addr=mbi.BaseAddress+mbi.RegionSize
        if (mbi.state==S.MEMORY_STATE.MEM_COMMIT and
                mbi.protect in allowed and mbi.RegionSize>0):
            try:
                data=pymem.memory.read_bytes(pm.process_handle,addr,
                    mbi.RegionSize-(addr-mbi.BaseAddress))
                for m in re.finditer(pattern,data,re.DOTALL):
                    found.append(addr+m.span()[0])
                n+=1
                if progress_cb and n%50==0: progress_cb(len(found))
            except: pass
        addr=next_addr
    return found

def narrow_scan(pm, candidates, val_bytes):
    size = len(val_bytes)
    kept = []
    for a in candidates:
        try:
            if pymem.memory.read_bytes(pm.process_handle, a, size) == val_bytes:
                kept.append(a)
        except:
            pass
    return kept

def pointer_scan(pm, target, max_off=0x800, stop_evt=None, progress_cb=None):
    """掃描所有指向 target 附近的指標"""
    results=[]; addr=0; limit=0x7FFFFFFF0000; n=0
    allowed={S.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
             S.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READONLY}
    while addr<limit:
        if stop_evt and stop_evt.is_set(): break
        try: mbi=pymem.memory.virtual_query(pm.process_handle,addr)
        except: break
        next_addr=mbi.BaseAddress+mbi.RegionSize
        if (mbi.state==S.MEMORY_STATE.MEM_COMMIT and
                mbi.protect in allowed and mbi.RegionSize>=8):
            try:
                size=mbi.RegionSize-(addr-mbi.BaseAddress)
                data=pymem.memory.read_bytes(pm.process_handle,addr,size)
                for i in range(0,len(data)-7,8):
                    val=struct.unpack_from('<Q',data,i)[0]
                    if target-max_off<=val<=target+max_off:
                        results.append((addr+i, target-val))  # (ptr_addr, offset=target-ptr_value)
                n+=1
                if progress_cb and n%30==0: progress_cb(len(results))
            except: pass
        addr=next_addr
    return results

def pointer_rescan(pm, prev, new_target, max_off=0x800):
    """用新目標位址縮小指標結果
    offset = target - ptr_value 是固定的物件內偏移
    所以 target = v + offset，驗證 v + offset ≈ new_target
    """
    kept = []
    for ptr_addr, offset in prev:
        v = read8(pm, ptr_addr)
        if v is None: continue
        if abs((v + offset) - new_target) <= max_off:
            kept.append((ptr_addr, offset))
    return kept

def resolve_ptr(pm, ptr_addr, offset):
    """讀取指標位址的值，加上 offset 得到目標位址
    offset = target - ptr_value（物件內固定偏移）
    target = ptr_value + offset
    """
    v = read8(pm, ptr_addr)
    if v is None: return None
    return v + offset


def resolve_ml_ptr(pm, chain):
    """解析多層指標鏈
    chain = {'rel_base': int, 'offsets': [off_outer, ..., off_inner]}
    解引用順序：
      addr = mod_base + rel_base
      for off in offsets[:-1]:
          v = read_ptr(addr); addr = v + off  ← 中間層
      hp_addr = read_ptr(addr) + offsets[-1]  ← 最後一層
    """
    mod_base = get_module_base(pm)
    if not mod_base: return None
    addr = mod_base + chain['rel_base']
    for off in chain['offsets'][:-1]:
        v = read8(pm, addr)
        if v is None: return None
        addr = v + off
    v = read8(pm, addr)
    if v is None: return None
    return v + chain['offsets'][-1]

def multilevel_ptr_scan(pm, target_addr, max_depth=3, max_off=0x800,
                         stop_evt=None, progress_cb=None):
    """BFS 反向多層指標掃描。
    從 target_addr 逆向追蹤，找出能到達它的靜態（模組內）指標鏈。
    每層做一次全記憶體掃描。

    返回: list of {'rel_base':int, 'offsets':[off,...], 'depth':int}
      rel_base  = 靜態根指標相對模組基址的偏移
      offsets   = 由外到內各層偏移（最後一個是直接加到 HP 位址的偏移）
    """
    mod_base = get_module_base(pm) or 0
    allowed = {S.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
               S.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
               S.MEMORY_PROTECTION.PAGE_READWRITE,
               S.MEMORY_PROTECTION.PAGE_READONLY}

    results = []
    # {target_addr: chain_from_here_to_hp}  chain=[(ptr_addr, off),...]  外→內
    current_targets = {target_addr: []}
    seen_ptr_addrs = set()

    for depth in range(max_depth):
        if not current_targets or (stop_evt and stop_evt.is_set()):
            break
        if progress_cb:
            progress_cb(f"多層掃描 第{depth+1}層（目標 {len(current_targets)} 個）...")

        all_t = list(current_targets.keys())
        min_t = min(all_t) - max_off
        max_t = max(all_t) + max_off

        next_targets = {}
        addr = 0; limit = 0x7FFFFFFF0000; n = 0

        while addr < limit:
            if stop_evt and stop_evt.is_set(): return results
            try: mbi = pymem.memory.virtual_query(pm.process_handle, addr)
            except: break
            next_addr = mbi.BaseAddress + mbi.RegionSize
            if (mbi.state == S.MEMORY_STATE.MEM_COMMIT and
                    mbi.protect in allowed and mbi.RegionSize >= 8):
                try:
                    size = mbi.RegionSize - (addr - mbi.BaseAddress)
                    data = pymem.memory.read_bytes(pm.process_handle, addr, size)
                    for i in range(0, len(data) - 7, 8):
                        ptr_addr = addr + i
                        if ptr_addr in seen_ptr_addrs: continue
                        val = struct.unpack_from('<Q', data, i)[0]
                        if not (min_t <= val <= max_t): continue
                        for t_addr, chain_to_hp in current_targets.items():
                            if abs(val - t_addr) > max_off: continue
                            off = t_addr - val
                            new_chain = [(ptr_addr, off)] + chain_to_hp
                            if is_module_addr(pm, ptr_addr) and mod_base:
                                offsets = [o for _, o in new_chain]
                                results.append({
                                    'rel_base': ptr_addr - mod_base,
                                    'offsets': offsets,
                                    'depth': depth + 1
                                })
                            elif ptr_addr not in next_targets:
                                next_targets[ptr_addr] = new_chain
                            seen_ptr_addrs.add(ptr_addr)
                            break
                    n += 1
                    if progress_cb and n % 30 == 0:
                        progress_cb(f"第{depth+1}層 找到鏈 {len(results)} 條...")
                except: pass
            addr = next_addr

        current_targets = next_targets

    return results
# ════════════════════════════════════════════════════════════════════
#  角色 HP 管理器
#  核心概念：
#  每個角色有一個 Entry，包含：
#    - candidates: 目前候選動態位址
#    - ptr_candidates: 指標掃描候選
#    - stable_ptr: 已確認穩定的指標 (ptr_addr, offset, rel_base)
#    - 一旦有 stable_ptr，重啟後自動解析，不需重掃
# ════════════════════════════════════════════════════════════════════
class CharEntry:
    def __init__(self, name, note=""):
        self.name    = name
        self.note    = note
        self.candidates  = []      # 動態掃描候選位址
        self.ptr_candidates = []   # 指標掃描候選 [(ptr_addr,offset),...]
        self.stable_ptr  = None    # 舊版單層指標 {'ptr_addr','offset','rel_base'}
        self.ptr_chain   = None    # 多層指標鏈 {'rel_base','offsets','depth'}
        self.locked   = False
        self.lock_val = None       # 鎖定目標 HP 值
        self.job      = None       # after() id

    def get_addr(self, pm):
        """取得當前 HP 位址。優先用多層鏈，其次舊版 stable_ptr，最後回退候選"""
        if self.ptr_chain and pm:
            return resolve_ml_ptr(pm, self.ptr_chain)
        if self.stable_ptr and pm:
            sp=self.stable_ptr
            mod_base=get_module_base(pm)
            ptr_addr=(mod_base+sp['rel_base'] if sp.get('rel_base') is not None
                      else sp['ptr_addr'])
            return resolve_ptr(pm,ptr_addr,sp['offset'])
        if self.candidates:
            return self.candidates[0]
        return None

    def read_hp(self, pm):
        a=self.get_addr(pm)
        return rdi(pm,a) if a else None

    def write_hp(self, pm, v):
        a=self.get_addr(pm)
        if a: wdi(pm,a,v); return True
        return False

    def has_stable(self):
        return self.ptr_chain is not None or self.stable_ptr is not None

    def stable_label(self):
        if self.ptr_chain:   return f"★{self.ptr_chain['depth']}"
        if self.stable_ptr:  return "★"
        return "○"

    def to_dict(self):
        return {'name':self.name,'note':self.note,
                'stable_ptr':self.stable_ptr,'ptr_chain':self.ptr_chain,
                'locked':self.locked,'lock_val':self.lock_val}

    @classmethod
    def from_dict(cls, d):
        e=cls(d['name'],d.get('note',''))
        e.stable_ptr=d.get('stable_ptr')
        e.ptr_chain =d.get('ptr_chain')
        e.locked   =d.get('locked', False)
        e.lock_val =d.get('lock_val', None)
        return e

# ════════════════════════════════════════════════════════════════════
BG="#1e1e2e"; BG2="#313244"; BG3="#181825"
FG="#cdd6f4"; ACC="#89b4fa"; GRN="#a6e3a1"
RED="#f38ba8"; YEL="#f9e2af"; GRAY="#6c7086"
LINE="#45475a"; PURPLE="#cba6f7"; TEAL="#94e2d5"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wartales Trainer  v9")
        self.configure(bg=BG); self.resizable(False,False)
        self._pm=None; self._scanning=False
        self._stop=threading.Event(); self._lock_jobs={}
        self._addrs={k:[] for k in ('gold','weight','spd','mv','rng')}

        # HP 角色列表
        self._chars=[]          # [CharEntry, ...]
        # 全局 HP 掃描候選（未命名前的暫存）
        self._hp_pool=[]

        self._build()
        self._load_data()
        self._attach()
        # 啟動定時刷新（顯示當前HP值）
        self._refresh_loop()

    # ── 連接 ────────────────────────────────────────────────────────
    def _attach(self):
        try:
            if self._pm: self._pm.close_process()
        except: pass
        try:
            self._pm=pymem.Pymem("Wartales.exe")
            self.proc_v.set(f"✅ 已連接  PID:{self._pm.process_id}")
            self.proc_l.config(fg=GRN); self._st("連接成功",GRN)
            # 重連後，嘗試用 stable_ptr 自動解析所有角色
            self._auto_resolve_all()
        except:
            self._pm=None
            self.proc_v.set("找不到 Wartales.exe")
            self.proc_l.config(fg=RED)

    def _chk(self):
        if not self._pm: self._attach()
        if not self._pm: messagebox.showwarning("未連接","請先啟動遊戲"); return False
        return True

    def _auto_resolve_all(self):
        """重連後清空舊動態位址，用穩定指標鏈重新解析；有鎖定的角色自動恢復鎖定"""
        if not self._pm: return
        for c in self._chars:
            c.candidates = []           # 舊 session 的動態位址，重開後一律失效
            if c.has_stable():
                addr = c.get_addr(self._pm)
                if addr is not None:
                    hp = rdi(self._pm, addr)
                    if hp is not None:
                        c.candidates = [addr]
            # 若上次關閉時是鎖定狀態，且現在位址有效 → 自動恢復鎖定迴圈
            if c.locked and c.lock_val is not None and c.candidates:
                if c.job:                    # 先取消舊迴圈，避免重連時雙重寫入
                    self.after_cancel(c.job)
                c.job = None
                self._do_char_lock(c, c.lock_val)
        self._refresh_char_list()

    # ── 背景掃描 ────────────────────────────────────────────────────
    def _bg(self, fn, on_done, status_v=None, btn=None, restore_cmd=None):
        if self._scanning: messagebox.showwarning("提示","掃描中"); return
        self._scanning=True; self._stop.clear()
        if btn: btn.config(text="⏹ 停止",bg=RED,
                           command=lambda:self._stop.set())
        if status_v: status_v.set("掃描中...")
        def worker():
            r=fn()
            self.after(0,lambda:self._bg_done(r,on_done,status_v,btn,restore_cmd))
        threading.Thread(target=worker,daemon=True).start()

    def _bg_done(self,r,on_done,status_v,btn,restore_cmd=None):
        self._scanning=False
        if btn:
            kw=dict(text="🔍 掃描",bg=ACC)
            if restore_cmd: kw['command']=restore_cmd
            btn.config(**kw)
        on_done(r)

    # ── 定時刷新 ────────────────────────────────────────────────────
    def _refresh_loop(self):
        try: self._refresh_char_list()
        except: pass
        self.after(1000, self._refresh_loop)

    # ════════════════════════════════════════════════════════════════
    #  UI
    # ════════════════════════════════════════════════════════════════
    def _build(self):
        hdr=tk.Frame(self,bg=BG3,pady=10); hdr.pack(fill="x")
        tk.Label(hdr,text="⚔  Wartales Trainer",
                 font=("Segoe UI",14,"bold"),bg=BG3,fg=ACC).pack()
        tk.Label(hdr,text="v9 — 自動指標學習，重啟後自動恢復",
                 font=("Segoe UI",8),bg=BG3,fg=GRAY).pack()

        pr=tk.Frame(self,bg=BG,pady=5); pr.pack(fill="x",padx=14)
        tk.Label(pr,text="狀態：",bg=BG,fg=FG,font=("Segoe UI",9)).pack(side="left")
        self.proc_v=tk.StringVar(value="未連接")
        self.proc_l=tk.Label(pr,textvariable=self.proc_v,bg=BG,fg=RED,
                              font=("Segoe UI",9,"bold"))
        self.proc_l.pack(side="left")
        self._mb(pr,"🔌 重連",self._attach,ACC,8).pack(side="right")
        tk.Frame(self,bg=LINE,height=1).pack(fill="x",padx=14)

        nb=tk.Frame(self,bg=BG); nb.pack(fill="both",expand=True,padx=14,pady=6)
        self._tabs=[]; self._tbns=[]
        bar=tk.Frame(nb,bg=BG); bar.pack(fill="x")
        cont=tk.Frame(nb,bg=BG2,highlightthickness=1,highlightbackground=LINE)
        cont.pack(fill="both",expand=True)

        for i,(lbl,fn) in enumerate([
            ("❤️ HP",self._pg_hp),
            ("🪙 金幣",self._pg_gold),
            ("🎒 負重",self._pg_weight),
            ("⚡ 移動",self._pg_move),
            ("🎯 攻距",self._pg_range)]):
            f=tk.Frame(cont,bg=BG2); self._tabs.append(f); fn(f)
            b=tk.Button(bar,text=lbl,bg=BG2 if i==0 else BG,fg=FG,
                        font=("Segoe UI",8,"bold"),relief="flat",
                        padx=10,pady=5,cursor="hand2",bd=0,
                        activebackground=BG2,activeforeground=ACC,
                        command=lambda i=i:self._sw(i))
            b.pack(side="left"); self._tbns.append(b)
        self._sw(0)

        tk.Frame(self,bg=LINE,height=1).pack(fill="x",padx=14)
        self._stv=tk.StringVar(value="就緒")
        self._stl=tk.Label(self,textvariable=self._stv,bg=BG,fg=GRAY,
                            font=("Segoe UI",8),anchor="w")
        self._stl.pack(fill="x",padx=14,pady=3)

    def _sw(self,idx):
        for f in self._tabs: f.pack_forget()
        self._tabs[idx].pack(fill="both",expand=True,padx=8,pady=8)
        for i,b in enumerate(self._tbns):
            b.config(bg=BG2 if i==idx else BG,fg=ACC if i==idx else FG)

    def _mb(self,p,t,c,col,w=8):
        return tk.Button(p,text=t,command=c,bg=col,fg=BG3,
                         font=("Segoe UI",8,"bold"),relief="flat",
                         padx=6,pady=4,cursor="hand2",width=w,
                         activebackground=col,activeforeground=BG3)

    def _st(self,msg,col=None):
        self._stv.set(msg); self._stl.config(fg=col or GRAY)

    # ════════════════════════════════════════════════════════════════
    #  HP 頁面
    # ════════════════════════════════════════════════════════════════
    def _pg_hp(self,p):
        # ── 說明 ──────────────────────────────────────────────────
        tk.Label(p,
            text="【首次設定角色】掃描 → 縮小 → 加入清單 → 程式自動學習指標\n"
                 "【之後重開遊戲】直接連線，程式自動恢復所有角色 HP 位址",
            bg=BG2,fg=FG,font=("Segoe UI",8),
            justify="left",wraplength=430).pack(anchor="w",padx=8,pady=(6,2))

        # ── 掃描列 ────────────────────────────────────────────────
        sr=tk.Frame(p,bg=BG2); sr.pack(fill="x",padx=6,pady=3)
        tk.Label(sr,text="HP：",bg=BG2,fg=FG,font=("Segoe UI",9)).pack(side="left")
        self._v_hp=tk.StringVar(value="100")
        tk.Entry(sr,textvariable=self._v_hp,bg=BG,fg=FG,insertbackground=FG,
                 font=("Consolas",10),width=8,relief="flat",
                 highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC
                 ).pack(side="left",ipady=3,padx=4)
        self._btn_hp1=self._mb(sr,"🔍 掃描",self._hp_first,ACC,7)
        self._btn_hp1.pack(side="left",padx=2)
        self._mb(sr,"🔍 縮小",self._hp_narrow,YEL,6).pack(side="left",padx=2)
        self._mb(sr,"🗑 清除",self._hp_clear,LINE,6).pack(side="left",padx=2)

        self._hp_pool_v=tk.StringVar(value="尚未掃描")
        tk.Label(p,textvariable=self._hp_pool_v,
                 bg=BG2,fg=GRAY,font=("Segoe UI",7),anchor="w").pack(fill="x",padx=8)

        pf=tk.Frame(p,bg=BG2); pf.pack(fill="x",padx=6)
        sb=tk.Scrollbar(pf,bg=BG2,troughcolor=BG2); sb.pack(side="right",fill="y")
        self._pool_lb=tk.Listbox(pf,bg=BG,fg=FG,font=("Consolas",8),height=3,
                                  relief="flat",selectmode="extended",
                                  highlightthickness=1,highlightbackground=LINE,
                                  selectbackground=PURPLE,selectforeground=BG3,
                                  yscrollcommand=sb.set)
        self._pool_lb.pack(side="left",fill="x",expand=True)
        sb.config(command=self._pool_lb.yview)

        ar=tk.Frame(p,bg=BG2); ar.pack(fill="x",padx=6,pady=2)
        self._mb(ar,"➕ 加入角色清單",self._add_char,PURPLE,14).pack(side="left")
        tk.Label(ar,text="← 選取後命名加入",bg=BG2,fg=GRAY,
                 font=("Segoe UI",7)).pack(side="left",padx=6)

        tk.Frame(p,bg=LINE,height=1).pack(fill="x",padx=6,pady=3)

        # ── 角色清單 ──────────────────────────────────────────────
        hdr2=tk.Frame(p,bg=BG2); hdr2.pack(fill="x",padx=6)
        tk.Label(hdr2,text="角色清單",bg=BG2,fg=GRN,
                 font=("Segoe UI",9,"bold")).pack(side="left")
        tk.Label(hdr2,text="（★=已學習指標，重啟自動恢復）",
                 bg=BG2,fg=TEAL,font=("Segoe UI",7)).pack(side="left",padx=6)

        cf=tk.Frame(p,bg=BG2); cf.pack(fill="x",padx=6)
        sb2=tk.Scrollbar(cf,bg=BG2,troughcolor=BG2); sb2.pack(side="right",fill="y")
        self._char_lb=tk.Listbox(cf,bg=BG,fg=FG,font=("Consolas",9),height=5,
                                  relief="flat",selectmode="extended",
                                  highlightthickness=1,highlightbackground=LINE,
                                  selectbackground=GRN,selectforeground=BG3,
                                  yscrollcommand=sb2.set)
        self._char_lb.pack(side="left",fill="x",expand=True)
        sb2.config(command=self._char_lb.yview)
        self._char_lb.bind("<Double-Button-1>",self._char_edit)

        # ── 操作列 ────────────────────────────────────────────────
        cr=tk.Frame(p,bg=BG2); cr.pack(fill="x",padx=6,pady=3)
        tk.Label(cr,text="HP值：",bg=BG2,fg=FG,font=("Segoe UI",9)).pack(side="left")
        self._v_hp_w=tk.StringVar(value="9999")
        tk.Entry(cr,textvariable=self._v_hp_w,bg=BG,fg=FG,insertbackground=FG,
                 font=("Consolas",10),width=7,relief="flat",
                 highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC
                 ).pack(side="left",ipady=3,padx=4)
        for sv,st in [(9999,"9999"),(99999,"99999")]:
            tk.Button(cr,text=st,bg=LINE,fg=FG,font=("Segoe UI",7),
                      relief="flat",padx=4,pady=1,cursor="hand2",
                      activebackground=ACC,activeforeground=BG3,
                      command=lambda v=sv:self._v_hp_w.set(str(v))
                     ).pack(side="left",padx=1)
        self._mb(cr,"✏️ 寫入",self._char_write,GRN,7).pack(side="left",padx=4)
        self._mb(cr,"🔒 鎖定",self._char_lock,RED,7).pack(side="left",padx=2)
        self._mb(cr,"🔓 解鎖",self._char_unlock,LINE,7).pack(side="left",padx=2)
        self._mb(cr,"🗑 移除",self._char_remove,LINE,7).pack(side="left",padx=2)
        self._mb(cr,"🔗 多層掃描",self._char_ml_scan,TEAL,9).pack(side="left",padx=2)
        tk.Label(p,text="雙擊編輯名稱/附註  ｜  多層掃描：HP縮到<5個後選角色觸發",
                 bg=BG2,fg=GRAY,font=("Segoe UI",7)).pack(anchor="w",padx=8)

    # ── HP 掃描 ─────────────────────────────────────────────────────
    def _hp_first(self):
        if not self._chk(): return
        try: v=int(self._v_hp.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        vb=struct.pack('<i',v)
        def do():
            def cb(n):
                self.after(0,lambda:self._hp_pool_v.set(f"找到 {n} 個..."))
            return scan_value(self._pm,vb,self._stop,cb)
        def done(r):
            self._hp_pool=r; self._refresh_pool()
            self._hp_pool_v.set(f"找到 {len(r)} 個  →  讓HP改變後按縮小")
            self._btn_hp1.config(text="🔍 掃描",bg=ACC,command=self._hp_first)
        self._btn_hp1.config(text="⏹ 停止",bg=RED,command=lambda:self._stop.set())
        self._bg(do,done,self._hp_pool_v,self._btn_hp1,restore_cmd=self._hp_first)

    def _hp_narrow(self):
        if not self._chk(): return
        if not self._hp_pool:
            messagebox.showwarning("提示","請先掃描"); return
        try: v = int(self._v_hp.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        vb = struct.pack('<i', v)
        self._hp_pool = narrow_scan(self._pm, self._hp_pool, vb)
        self._refresh_pool()
        n = len(self._hp_pool)
        self._hp_pool_v.set(f"縮小後剩 {n} 個{'  →  繼續讓HP改變再縮小' if n > 5 else '  →  可加入角色清單了'}")
        self._st(f"縮小後剩 {n} 個", GRN if n else RED)

    def _hp_clear(self):
        self._hp_pool=[]; self._refresh_pool(); self._hp_pool_v.set("已清除")

    def _refresh_pool(self):
        self._pool_lb.delete(0,"end")
        char_addrs={c.candidates[0] for c in self._chars if c.candidates}
        for a in self._hp_pool[:200]:
            cur=rdi(self._pm,a) if self._pm else "?"
            tag=" ✅" if a in char_addrs else ""
            self._pool_lb.insert("end",f"  HP={str(cur):<6}  {a:#010x}{tag}")
        if len(self._hp_pool)>200:
            self._pool_lb.insert("end",f"  ... 共{len(self._hp_pool)}筆，請繼續縮小")

    # ── 加入角色 ────────────────────────────────────────────────────
    def _add_char(self):
        sel=self._pool_lb.curselection()
        if not sel: messagebox.showwarning("提示","請先在候選池選取位址"); return
        added=0
        for i in sel:
            if i>=len(self._hp_pool): continue
            addr=self._hp_pool[i]
            if any(addr in (c.candidates[:1] or []) for c in self._chars): continue
            r=self._name_dlg(f"角色{len(self._chars)+1}")
            if r is None: continue
            c=CharEntry(r[0],r[1])
            c.candidates=[addr]
            self._chars.append(c)
            added+=1
            # 立即在背景做指標掃描
            self._bg_learn_ptr(c)
        self._refresh_char_list()
        self._refresh_pool()
        if added: self._st(f"加入 {added} 個角色，開始學習指標...",TEAL)

    def _bg_learn_ptr(self, char):
        """背景自動做指標掃描，學習該角色的穩定指標"""
        if not self._pm or not char.candidates: return
        target=char.candidates[0]
        self._st(f"正在學習 {char.name} 的指標...",TEAL)

        def do():
            def cb(n): pass  # 靜默掃描
            return pointer_scan(self._pm,target,max_off=0x800,
                                stop_evt=self._stop,progress_cb=cb)
        def done(results):
            char.ptr_candidates=results
            self._try_stabilize(char)
            if not char.stable_ptr:
                self._st(f"{char.name}：單層找不到靜態指標（{len(results)} 個候選），建議按「多層掃描」",YEL)
        self._bg(do,done)

    def _try_stabilize(self, char):
        """從單層指標候選中找靜態指標，設為 stable_ptr（精確位址匹配）"""
        if not self._pm or not char.ptr_candidates or not char.candidates: return
        known_hp_addr = char.candidates[0]
        mod_base=get_module_base(self._pm) or 0
        static_set=set(pa for pa,off in char.ptr_candidates
                       if is_module_addr(self._pm,pa))
        static_ptrs=[(pa,off) for pa,off in char.ptr_candidates if pa in static_set]
        candidates=static_ptrs or char.ptr_candidates

        valid=[]
        for pa,off in candidates[:2000]:
            target = resolve_ptr(self._pm, pa, off)
            if target is None: continue
            if target == known_hp_addr:           # 精確位址匹配，不再用值相等
                is_static = pa in static_set      # 用快取，不再重複 syscall
                rel=pa-mod_base if (is_static and mod_base) else None
                valid.append({'ptr_addr':pa,'offset':off,
                              'rel_base':rel,'is_static':is_static})

        if valid:
            s=[v for v in valid if v['is_static']]
            char.stable_ptr=(s or valid)[0]
            self._save_data()
            self._refresh_char_list()
            if s:
                self._st(f"{char.name}：單層靜態指標學習成功，亦可用多層掃描提高穩定性",GRN)
            else:
                self._st(f"{char.name}：單層動態指標（重啟可能失效），建議按多層掃描",YEL)
        else:
            self._st(f"{char.name}：單層無靜態指標，請點「多層掃描」",YEL)

    def _try_stabilize_ml(self, char, ml_results):
        """從多層指標掃描結果中選最佳鏈"""
        if not self._pm or not ml_results or not char.candidates: return
        known_hp_addr = char.candidates[0]
        valid = []
        for r in ml_results:
            resolved = resolve_ml_ptr(self._pm, r)
            if resolved == known_hp_addr:
                valid.append(r)
        if valid:
            valid.sort(key=lambda r: r['depth'])
            char.ptr_chain = valid[0]
            self._save_data()
            self._refresh_char_list()
            self._st(f"{char.name}：{valid[0]['depth']} 層指標鏈學習成功！重啟可自動恢復",GRN)
        else:
            self._st(f"{char.name}：多層掃描未驗證到有效鏈，請先縮小 HP 候選再掃",YEL)

    # ── 角色清單 ────────────────────────────────────────────────────
    def _refresh_char_list(self):
        try:
            # 保留選取狀態
            sel = list(self._char_lb.curselection())
            self._char_lb.delete(0, "end")
            for c in self._chars:
                hp   = c.read_hp(self._pm) if self._pm else None
                lock = "🔒" if c.locked else "  "
                star = c.stable_label()
                note = f"  [{c.note}]" if c.note else ""
                hp_s = str(hp) if hp is not None else "?"
                self._char_lb.insert("end",
                    f" {lock}{star} {c.name:<14} HP={hp_s:<6}{note}")
            # 恢復選取
            for i in sel:
                if i < self._char_lb.size():
                    self._char_lb.selection_set(i)
        except: pass

    def _char_edit(self,_=None):
        sel=self._char_lb.curselection()
        if not sel: return
        c=self._chars[sel[0]]
        r=self._name_dlg(c.name,c.note)
        if r: c.name,c.note=r; self._refresh_char_list(); self._save_data()

    def _char_sel(self):
        sel=self._char_lb.curselection()
        return [self._chars[i] for i in sel] if sel else []

    def _char_write(self):
        if not self._chk(): return
        t=self._char_sel()
        if not t: messagebox.showwarning("提示","請先選取角色"); return
        try: v=int(self._v_hp_w.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        ok=sum(1 for c in t if c.write_hp(self._pm,v))
        self._refresh_char_list()
        self._st(f"HP={v} 寫入 {ok}/{len(t)} 個角色",GRN)

    def _char_lock(self):
        if not self._chk(): return
        t=self._char_sel()
        if not t: messagebox.showwarning("提示","請先選取角色"); return
        try: v=int(self._v_hp_w.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        for c in t:
            if c.locked: continue
            c.locked=True; c.lock_val=v; self._do_char_lock(c,v)
        self._save_data()
        self._refresh_char_list()
        self._st(f"鎖定 HP={v}",RED)

    def _do_char_lock(self,char,val):
        if not char.locked or not self._pm: return
        char.write_hp(self._pm,val)
        char.job=self.after(150,lambda:self._do_char_lock(char,val))

    def _char_unlock(self):
        for c in (self._char_sel() or self._chars):
            if c.job: self.after_cancel(c.job)
            c.locked=False; c.job=None
        self._save_data()
        self._refresh_char_list(); self._st("已解鎖",GRAY)

    def _char_remove(self):
        sel=self._char_lb.curselection()
        if not sel: return
        for i in sorted(sel,reverse=True):
            c=self._chars[i]
            if c.job: self.after_cancel(c.job)
            del self._chars[i]
        self._refresh_char_list(); self._save_data()

    def _char_ml_scan(self):
        """對選取角色執行多層指標掃描（需 HP 候選已縮到 5 個以下）"""
        if not self._chk(): return
        t=self._char_sel()
        if not t: messagebox.showwarning("提示","請先在角色清單選取角色"); return
        if len(self._hp_pool) > 5:
            messagebox.showwarning("提示",
                f"HP 候選還有 {len(self._hp_pool)} 個，請先縮小到 5 個以下再做多層掃描")
            return
        for c in t:
            if not c.candidates:
                if self._hp_pool and len(self._hp_pool) <= 5:
                    # 指標失效後重掃：從候選池借用位址並更新角色
                    c.candidates = [self._hp_pool[0]]
                    self._st(f"{c.name}：自動借用候選池位址 {self._hp_pool[0]:#x}",TEAL)
                else:
                    self._st(f"{c.name} 無 HP 位址，請先縮小 HP 候選到 5 個以下",RED)
                    continue
            target=c.candidates[0]
            self._st(f"正在多層掃描 {c.name}（最多3層，需時數分鐘）...",TEAL)
            def do(tgt=target):
                def cb(msg):
                    self.after(0,lambda:self._st(msg,TEAL))
                return multilevel_ptr_scan(self._pm,tgt,max_depth=3,
                                           max_off=0x800,stop_evt=self._stop,
                                           progress_cb=cb)
            def done(results,char=c):
                self._st(f"{char.name}：多層掃描完成，找到 {len(results)} 條候選鏈",
                         GRN if results else YEL)
                self._try_stabilize_ml(char,results)
            self._bg(do,done,btn=self._btn_hp1,restore_cmd=self._hp_first)
            break  # 一次只掃一個角色（背景掃描有 lock）

    # ── 對話框 ──────────────────────────────────────────────────────
    def _name_dlg(self,name="",note=""):
        win=tk.Toplevel(self); win.title("角色名稱")
        win.configure(bg=BG); win.resizable(False,False); win.grab_set()
        win.geometry("+%d+%d"%(self.winfo_x()+80,self.winfo_y()+130))
        tk.Label(win,text="角色名稱：",bg=BG,fg=FG,
                 font=("Segoe UI",9)).pack(padx=14,pady=(12,2),anchor="w")
        vn=tk.StringVar(value=name)
        en=tk.Entry(win,textvariable=vn,bg=BG2,fg=FG,insertbackground=FG,
                    font=("Segoe UI",10),width=18,relief="flat",
                    highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC)
        en.pack(padx=14,pady=(2,6),ipady=4); en.focus(); en.select_range(0,"end")
        tk.Label(win,text="附註（可留空）：",bg=BG,fg=FG,
                 font=("Segoe UI",9)).pack(padx=14,anchor="w")
        vt=tk.StringVar(value=note)
        tk.Entry(win,textvariable=vt,bg=BG2,fg=FG,insertbackground=FG,
                 font=("Segoe UI",9),width=18,relief="flat",
                 highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC
                 ).pack(padx=14,pady=(2,10),ipady=4)
        result=[None]
        def ok():
            result[0]=(vn.get().strip() or name,vt.get().strip()); win.destroy()
        en.bind("<Return>",lambda _:ok())
        br=tk.Frame(win,bg=BG); br.pack(pady=(0,10))
        self._mb(br,"確定",ok,GRN,6).pack(side="left",padx=6)
        self._mb(br,"取消",win.destroy,LINE,6).pack(side="left",padx=6)
        win.wait_window(); return result[0]

    # ── 資料存取 ────────────────────────────────────────────────────
    def _save_data(self):
        try:
            with open(DATA_FILE,'w',encoding='utf-8') as f:
                json.dump([c.to_dict() for c in self._chars],
                          f,ensure_ascii=False,indent=2)
        except: pass

    def _load_data(self):
        try:
            if not os.path.exists(DATA_FILE): return
            with open(DATA_FILE,encoding='utf-8') as f:
                data=json.load(f)
            self._chars=[CharEntry.from_dict(d) for d in data]
            self._refresh_char_list()
            n=len(self._chars)
            stable=sum(1 for c in self._chars if c.has_stable())
            self._st(f"載入 {n} 個角色（{stable} 個已學習指標）",TEAL)
        except: pass

    # ════════════════════════════════════════════════════════════════
    #  其他頁面（金幣/負重/移動/攻距）
    # ════════════════════════════════════════════════════════════════
    def _simple_pg(self,p,key,title,hint,scan_fn,write_fn,
                   default,shortcuts=None,lock=False):
        tk.Label(p,text=title,bg=BG2,fg=ACC,
                 font=("Segoe UI",10,"bold")).pack(anchor="w",padx=6,pady=(8,2))
        tk.Label(p,text=hint,bg=BG2,fg=FG,font=("Segoe UI",8),
                 justify="left",wraplength=420).pack(anchor="w",padx=8)
        setattr(self,f"_v_{key}",tk.StringVar(value=default))
        r=tk.Frame(p,bg=BG2); r.pack(fill="x",padx=6,pady=4)
        tk.Entry(r,textvariable=getattr(self,f"_v_{key}"),
                 bg=BG,fg=FG,insertbackground=FG,font=("Consolas",11),width=12,
                 relief="flat",highlightthickness=1,
                 highlightbackground=LINE,highlightcolor=ACC
                 ).pack(side="left",ipady=4,padx=(0,4))
        if shortcuts:
            for sv,st in shortcuts:
                tk.Button(r,text=st,bg=LINE,fg=FG,font=("Segoe UI",8),
                          relief="flat",padx=5,pady=2,cursor="hand2",
                          activebackground=ACC,activeforeground=BG3,
                          command=lambda v=sv,k=key:getattr(self,f"_v_{k}").set(str(v))
                         ).pack(side="left",padx=2)
        btn=self._mb(r,"🔍 掃描",scan_fn,ACC,7)
        btn.pack(side="left",padx=4); setattr(self,f"_btn_{key}",btn)
        self._mb(r,"✏️ 寫入",write_fn,GRN,7).pack(side="left",padx=2)
        if lock:
            setattr(self,f"_lock_{key}",tk.BooleanVar(value=False))
            lb=tk.Button(r,text="🔒 鎖定",bg=LINE,fg=FG,
                         font=("Segoe UI",8,"bold"),relief="flat",
                         padx=6,pady=4,cursor="hand2",width=7,
                         command=lambda k=key:self._toggle_lock(k))
            lb.pack(side="left",padx=2)
            setattr(self,f"_lockbtn_{key}",lb)
        rv=tk.StringVar(value="尚未掃描"); setattr(self,f"_r_{key}",rv)
        tk.Label(p,textvariable=rv,bg=BG2,fg=GRAY,
                 font=("Segoe UI",7),anchor="w").pack(fill="x",padx=8)

    def _pg_gold(self,p):
        self._simple_pg(p,"gold","🪙 金幣","填當前金幣 → 掃描 → 填新值 → 寫入",
            self._scan_gold,self._write_gold,"0",
            shortcuts=[(99999,"10萬"),(999999,"100萬"),(9999999,"1000萬")])
    def _pg_weight(self,p):
        self._simple_pg(p,"weight","🎒 負重","填當前負重 → 掃描 → 填0 → 寫入/鎖定",
            self._scan_weight,self._write_weight,"50",
            shortcuts=[(0,"歸零"),(-9999,"無限")],lock=True)
    def _pg_move(self,p):
        self._simple_pg(p,"spd","⚡ 地圖速度","填3.0 → 掃描 → 填新速度",
            self._scan_spd,self._write_spd,"3.0",
            shortcuts=[(3.0,"預設"),(10.0,"快"),(30.0,"超速")])
        tk.Frame(p,bg=LINE,height=1).pack(fill="x",padx=6,pady=6)
        self._simple_pg(p,"mv","⚡ 戰鬥移動格","填當前格數 → 掃描 → 填新值",
            self._scan_mv,self._write_mv,"3",
            shortcuts=[(3,"預設"),(10,"10格"),(99,"無限")],lock=True)
    def _pg_range(self,p):
        self._simple_pg(p,"rng","🎯 攻擊距離","填當前格數 → 掃描 → 填新值",
            self._scan_rng,self._write_rng,"1",
            shortcuts=[(1,"近1"),(2,"矛2"),(6,"弓6"),(20,"遠20"),(99,"最大")],lock=True)

    def _toggle_lock(self,key):
        var=getattr(self,f"_lock_{key}"); btn=getattr(self,f"_lockbtn_{key}")
        if var.get():
            var.set(False); btn.config(text="🔒 鎖定",bg=LINE)
            if key in self._lock_jobs: self.after_cancel(self._lock_jobs.pop(key))
        else:
            if not self._addrs[key]: messagebox.showwarning("提示","請先掃描"); return
            var.set(True); btn.config(text="🔓 停止",bg=RED); self._do_lock(key)

    def _do_lock(self,key):
        if not getattr(self,f"_lock_{key}").get(): return
        if self._pm:
            try:
                v=float(getattr(self,f"_v_{key}").get())
                for a in self._addrs[key]:
                    if key=='spd': wdf(self._pm,a,v)
                    else: wdi(self._pm,a,int(v))
            except: pass
        self._lock_jobs[key]=self.after(150,lambda:self._do_lock(key))

    def _set_res(self,key,addrs):
        rv=getattr(self,f"_r_{key}"); n=len(addrs)
        if n==0: rv.set("❌ 找不到"); self._st("掃描無結果",RED)
        elif n>2000: rv.set(f"⚠ 太多({n})，輸入更精確的值")
        else:
            s=" ".join(f"{a:#x}" for a in addrs[:3])
            rv.set(f"✅ {n}個：{s}{'...' if n>3 else ''}")
            self._st(f"找到 {n} 個",GRN)

    def _do_scan(self,key,vb):
        if not self._chk(): return
        rv=getattr(self,f"_r_{key}"); btn=getattr(self,f"_btn_{key}")
        def do():
            def cb(n):
                self.after(0,lambda:rv.set(f"找到 {n} 個..."))
            return scan_value(self._pm,vb,self._stop,cb)
        def done(r):
            self._addrs[key]=r; self._set_res(key,r)
            btn.config(text="🔍 掃描",bg=ACC)
        btn.config(text="⏹ 停止",bg=RED,command=lambda:self._stop.set())
        rv.set("掃描中..."); self._bg(do,done,rv,btn)

    def _scan_gold(self):
        try: v=int(self._v_gold.get().replace(',',''))
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('gold',struct.pack('<I',enc_gold(v)))
    def _write_gold(self):
        if not self._pm or not self._addrs['gold']:
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_gold.get().replace(',',''))
        except: return
        for a in self._addrs['gold']: wdu(self._pm,a,enc_gold(v)); wdi(self._pm,a+4,v)
        self._st(f"金幣={v:,}",GRN)
    def _scan_weight(self):
        try: v=int(self._v_weight.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('weight',struct.pack('<i',v))
    def _write_weight(self):
        if not self._pm or not self._addrs['weight']:
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_weight.get())
        except: return
        for a in self._addrs['weight']: wdi(self._pm,a,v)
        self._st(f"負重={v}",GRN)
    def _scan_spd(self):
        try: v=float(self._v_spd.get())
        except: messagebox.showerror("錯誤","請輸入浮點數"); return
        self._do_scan('spd',struct.pack('<f',v))
    def _write_spd(self):
        if not self._pm or not self._addrs['spd']:
            messagebox.showwarning("提示","請先掃描"); return
        try: v=float(self._v_spd.get())
        except: return
        for a in self._addrs['spd']: wdf(self._pm,a,v)
        self._st(f"速度={v}",GRN)
    def _scan_mv(self):
        try: v=int(self._v_mv.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('mv',struct.pack('<i',v))
    def _write_mv(self):
        if not self._pm or not self._addrs['mv']:
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_mv.get())
        except: return
        for a in self._addrs['mv']: wdi(self._pm,a,v)
        self._st(f"移動格={v}",GRN)
    def _scan_rng(self):
        try: v=int(self._v_rng.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('rng',struct.pack('<i',v))
    def _write_rng(self):
        if not self._pm or not self._addrs['rng']:
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_rng.get())
        except: return
        for a in self._addrs['rng']: wdi(self._pm,a,v)
        self._st(f"攻距={v}",GRN)

    def destroy(self):
        self._stop.set()
        for jid in self._lock_jobs.values(): self.after_cancel(jid)
        for c in self._chars:
            if c.job: self.after_cancel(c.job)
        try:
            if self._pm: self._pm.close_process()
        except: pass
        super().destroy()

if __name__=="__main__":
    App().mainloop()
