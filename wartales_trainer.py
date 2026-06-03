#!/usr/bin/env python3
"""Wartales Trainer v10 — 全數值鎖定持久化，LED 進度條"""
import ctypes, ctypes.wintypes as _wt, sys, struct, threading, re, json, os, time
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

# ══════════════════════════════════════════════════════════════════
#  監聽 HP 寫入 — Windows x64 Debug API + 硬體中斷點（DR0 write 4B）
# ══════════════════════════════════════════════════════════════════
_k32 = ctypes.windll.kernel32

_TH32CS_SNAPTHREAD  = 0x4
_THREAD_ALL_ACCESS  = 0x1FFFFF
_CONTEXT_DBG_REGS   = 0x10010    # ContextFlags: only debug registers
_CONTEXT_FULL       = 0x10007F   # ContextFlags: integer + control + debug
_EXC_EVENT          = 1
_CRT_THREAD_EVENT   = 2
_CRT_PROC_EVENT     = 3
_EXIT_THREAD_EVENT  = 4
_EXIT_PROC_EVENT    = 5
_DBG_CONT           = 0x10002
_DBG_EXC_NH         = 0x80010001
_EXC_SINGLE_STEP    = 0x80000004
_EXC_BREAKPOINT     = 0x80000003
# DR7 = local-enable DR0 (bit0) | write cond (bits16-17=01) | 4-byte (bits18-19=11)
_DR7_WRITE4         = (0b11<<18)|(0b01<<16)|0x1  # 0x000D0001

# x64 CONTEXT offsets (winnt.h _CONTEXT, DECLSPEC_ALIGN(16))
_O_FLAGS=0x30; _O_DR0=0x48; _O_DR6=0x68; _O_DR7=0x70; _O_RIP=0xF8
_CTX_SZ=1232

class _TE32(ctypes.Structure):
    _fields_=[("dwSize",_wt.DWORD),("cntUsage",_wt.DWORD),
              ("th32ThreadID",_wt.DWORD),("th32OwnerProcessID",_wt.DWORD),
              ("tpBasePri",_wt.LONG),("tpDeltaPri",_wt.LONG),("dwFlags",_wt.DWORD)]

class _ER(ctypes.Structure):
    _fields_=[("ExceptionCode",ctypes.c_uint32),("ExceptionFlags",ctypes.c_uint32),
              ("ExceptionRecord",ctypes.c_void_p),("ExceptionAddress",ctypes.c_void_p),
              ("NumberParameters",ctypes.c_uint32),("ExceptionInformation",ctypes.c_uint64*15)]

class _EDI(ctypes.Structure):
    _fields_=[("ExceptionRecord",_ER),("dwFirstChance",ctypes.c_uint32)]

class _DEU(ctypes.Union):
    _fields_=[("Exception",_EDI),("pad",ctypes.c_uint8*160)]

class _DE(ctypes.Structure):
    _fields_=[("dwDebugEventCode",ctypes.c_uint32),("dwProcessId",ctypes.c_uint32),
              ("dwThreadId",ctypes.c_uint32),("u",_DEU)]

def _ctx_new():
    """x64 CONTEXT 需 16-byte 對齊，手動確保。返回 (raw_buf, aligned_ptr, buf_offset)"""
    raw=(ctypes.c_char*(_CTX_SZ+16))()
    base=ctypes.addressof(raw)
    off=(16-(base%16))%16
    ctypes.memset(base+off,0,_CTX_SZ)
    return raw, base+off, off

def _cr32(raw,off,field): return struct.unpack_from('<I',raw,off+field)[0]
def _cr64(raw,off,field): return struct.unpack_from('<Q',raw,off+field)[0]
def _cw32(raw,off,field,v): struct.pack_into('<I',raw,off+field,v&0xFFFFFFFF)
def _cw64(raw,off,field,v): struct.pack_into('<Q',raw,off+field,v&0xFFFFFFFFFFFFFFFF)

def _enum_threads(pid):
    snap=_k32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD,0)
    if snap in(-1,0xFFFFFFFF): return []
    te=_TE32(); te.dwSize=ctypes.sizeof(_TE32); tids=[]
    if _k32.Thread32First(snap,ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID==pid: tids.append(te.th32ThreadID)
            if not _k32.Thread32Next(snap,ctypes.byref(te)): break
    _k32.CloseHandle(snap); return tids

def _set_dr(tid, dr0, dr7):
    """設置某執行緒的 DR0（監聽地址）和 DR7（中斷點控制）"""
    ht=_k32.OpenThread(_THREAD_ALL_ACCESS,False,tid)
    if not ht: return
    _k32.SuspendThread(ht)
    raw,ptr,off=_ctx_new()
    _cw32(raw,off,_O_FLAGS,_CONTEXT_DBG_REGS)
    if _k32.GetThreadContext(ht,ctypes.c_void_p(ptr)):
        _cw64(raw,off,_O_DR0,dr0)
        _cw64(raw,off,_O_DR7,dr7)
        _cw32(raw,off,_O_FLAGS,_CONTEXT_DBG_REGS)
        _k32.SetThreadContext(ht,ctypes.c_void_p(ptr))
    _k32.ResumeThread(ht); _k32.CloseHandle(ht)

def _get_ctx(tid):
    """讀取執行緒目前的 DR6（觸發狀態）和 RIP（下一條指令位址）"""
    ht=_k32.OpenThread(_THREAD_ALL_ACCESS,False,tid)
    if not ht: return None
    raw,ptr,off=_ctx_new()
    _cw32(raw,off,_O_FLAGS,_CONTEXT_FULL)
    r=None
    if _k32.GetThreadContext(ht,ctypes.c_void_p(ptr)):
        r={'dr6':_cr64(raw,off,_O_DR6),'rip':_cr64(raw,off,_O_RIP)}
    _k32.CloseHandle(ht); return r

def _guess_write_instr(buf20, rip):
    """
    硬體 data BP 觸發時 RIP 已指向下一條指令。
    從 RIP 前的 15 個位元組逆向找「寫入記憶體」的指令。
    buf20: read_bytes(rip-15, 20)
    返回 (back_offset, instr_bytes)：back_offset 為負數（相對 rip）
    """
    for back in [3,4,6,7,2,5,8,9,10,1]:
        off=15-back
        if off<0: continue
        b=bytes(buf20[off:off+back])
        if not b: continue
        b0=b[0]
        # MOV [mem], r32
        if b0==0x89: return -back, b
        # MOV [mem], imm32
        if b0==0xC7: return -back, b
        # REX.W prefix + MOV
        if b0 in(0x48,0x4C,0x44,0x49,0x4D) and len(b)>=3 and b[1] in(0x89,0x8B): return -back,b
        # ADD/SUB/etc [mem], r
        if b0 in(0x01,0x09,0x11,0x19,0x21,0x29,0x31): return -back,b
    return -6, bytes(buf20[9:15])

def watch_hp_write(pid, target_addr, proc_handle, mod_base=0,
                   stop_evt=None, timeout=None, progress_cb=None):
    """
    持續監聽 target_addr 的所有寫入，直到 stop_evt 被設置。
    收集所有唯一寫入指令（去重），返回 list[dict] 或 {'error':str}。

    HP 減少可能來自多條路徑（直傷/技能/效果），需要全部 patch 才有效。
    每次 BP 觸發後 DR7 保持不變，中斷點自動繼續有效。
    """
    if not _k32.DebugActiveProcess(pid):
        err=ctypes.get_last_error()
        return {'error':f'DebugActiveProcess 失敗 (err={err})，請確認以管理員執行'}
    _k32.DebugSetProcessKillOnExit(False)

    bp_set=set(); results=[]; seen=set()
    evt=_DE(); start=time.time()

    def arm(tid):
        if tid not in bp_set:
            _set_dr(tid,target_addr,_DR7_WRITE4); bp_set.add(tid)

    def arm_all():
        for t in _enum_threads(pid): arm(t)

    def _timed_out():
        return timeout is not None and time.time()-start>=timeout

    try:
        arm_all()
        while not _timed_out():
            if stop_evt and stop_evt.is_set(): break
            if not _k32.WaitForDebugEvent(ctypes.byref(evt),200): continue

            code=evt.dwDebugEventCode; tid=evt.dwThreadId; pid2=evt.dwProcessId

            if code in(_CRT_PROC_EVENT,_CRT_THREAD_EVENT):
                arm(tid); _k32.ContinueDebugEvent(pid2,tid,_DBG_CONT)

            elif code==_EXIT_PROC_EVENT:
                break

            elif code==_EXC_EVENT:
                exc=evt.u.Exception.ExceptionRecord.ExceptionCode
                first=evt.u.Exception.dwFirstChance

                if exc==_EXC_BREAKPOINT and first:
                    arm_all(); _k32.ContinueDebugEvent(pid2,tid,_DBG_CONT)

                elif exc==_EXC_SINGLE_STEP:
                    ctx=_get_ctx(tid)
                    if ctx and (ctx['dr6']&0xF):
                        rip=ctx['rip']
                        try:
                            buf20=pymem.memory.read_bytes(proc_handle,rip-15,20)
                        except: buf20=bytes(20)
                        back,ibytes=_guess_write_instr(buf20,rip)
                        iaddr=rip+back
                        # 去重：同一指令地址只記一次
                        if iaddr not in seen:
                            seen.add(iaddr)
                            results.append({
                                'instr_addr':    iaddr,
                                'instr_bytes':   ibytes,
                                'module_offset': iaddr-mod_base if mod_base else 0,
                                'rip_after':     rip,
                            })
                            if progress_cb: progress_cb(len(results))
                        # 不 break，繼續收集更多路徑
                        _k32.ContinueDebugEvent(pid2,tid,_DBG_CONT)
                    else:
                        _k32.ContinueDebugEvent(pid2,tid,_DBG_EXC_NH)
                else:
                    cont=_DBG_CONT if not first else _DBG_EXC_NH
                    _k32.ContinueDebugEvent(pid2,tid,cont)
            else:
                _k32.ContinueDebugEvent(pid2,tid,_DBG_CONT)
    finally:
        for t in bp_set: _set_dr(t,0,0)
        _k32.DebugActiveProcessStop(pid)
    return results

def apply_nop_patch(proc_handle, addr, length):
    """把 addr 開始的 length 個位元組替換為 NOP (0x90)，返回原始位元組"""
    PAGE_EXECUTE_READWRITE=0x40
    orig=pymem.memory.read_bytes(proc_handle,addr,length)
    old=ctypes.c_uint32()
    _k32.VirtualProtectEx(proc_handle,ctypes.c_void_p(addr),length,
                          PAGE_EXECUTE_READWRITE,ctypes.byref(old))
    nops=(ctypes.c_char*length)(*(b'\x90'*length))
    _k32.WriteProcessMemory(proc_handle,ctypes.c_void_p(addr),nops,length,None)
    _k32.VirtualProtectEx(proc_handle,ctypes.c_void_p(addr),length,old,ctypes.byref(old))
    return bytes(orig)

# ── 常數 ────────────────────────────────────────────────────────────
RKEY=0x5b62db6d; RMUL=0x1F
SCAN_LIMIT=0x7FFFFFFF0000
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                         "wartales_data.json")
LOG_FILE  = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                         "wartales_debug.log")

def _log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}\n"
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line)
    except: pass

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
        return mbi.Type==0x1000000
    except: return False

# ── 掃描函式（progress_cb 統一簽名：cb(pct: 0.0~1.0, info)）────────
def scan_value(pm, val_bytes, stop_evt=None, progress_cb=None):
    pattern=re.escape(val_bytes); found=[]; addr=0; n=0
    allowed={S.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
             S.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READONLY}
    while addr<SCAN_LIMIT:
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
                if progress_cb and n%30==0:
                    progress_cb(addr/SCAN_LIMIT, len(found))
            except: pass
        addr=next_addr
    if progress_cb: progress_cb(1.0, len(found))
    return found

def narrow_scan(pm, candidates, val_bytes):
    size=len(val_bytes); kept=[]
    for a in candidates:
        try:
            if pymem.memory.read_bytes(pm.process_handle,a,size)==val_bytes:
                kept.append(a)
        except: pass
    return kept

def pointer_scan(pm, target, max_off=0x800, stop_evt=None, progress_cb=None):
    results=[]; addr=0; n=0
    allowed={S.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
             S.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READONLY}
    while addr<SCAN_LIMIT:
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
                        results.append((addr+i, target-val))
                n+=1
                if progress_cb and n%30==0:
                    progress_cb(addr/SCAN_LIMIT, len(results))
            except: pass
        addr=next_addr
    if progress_cb: progress_cb(1.0, len(results))
    return results

def resolve_ptr(pm, ptr_addr, offset):
    v=read8(pm,ptr_addr)
    if v is None: return None
    return v+offset

def resolve_ml_ptr(pm, chain):
    mod_base=get_module_base(pm)
    if not mod_base: return None
    addr=mod_base+chain['rel_base']
    for off in chain['offsets'][:-1]:
        v=read8(pm,addr)
        if v is None: return None
        addr=v+off
    v=read8(pm,addr)
    if v is None: return None
    return v+chain['offsets'][-1]

def multilevel_ptr_scan(pm, target_addr, max_depth=6, max_off=0x800,
                         stop_evt=None, progress_cb=None):
    mod_base=get_module_base(pm) or 0
    allowed={S.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
             S.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READWRITE,
             S.MEMORY_PROTECTION.PAGE_READONLY}
    results=[]; current_targets={target_addr:[]}; seen_ptr_addrs=set()
    for depth in range(max_depth):
        if not current_targets or (stop_evt and stop_evt.is_set()): break
        all_t=list(current_targets.keys())
        min_t=min(all_t)-max_off; max_t=max(all_t)+max_off
        next_targets={}; addr=0; n=0
        while addr<SCAN_LIMIT:
            if stop_evt and stop_evt.is_set(): return results
            try: mbi=pymem.memory.virtual_query(pm.process_handle,addr)
            except: break
            next_addr=mbi.BaseAddress+mbi.RegionSize
            if (mbi.state==S.MEMORY_STATE.MEM_COMMIT and
                    mbi.protect in allowed and mbi.RegionSize>=8):
                try:
                    size=mbi.RegionSize-(addr-mbi.BaseAddress)
                    data=pymem.memory.read_bytes(pm.process_handle,addr,size)
                    for i in range(0,len(data)-7,8):
                        ptr_addr=addr+i
                        if ptr_addr in seen_ptr_addrs: continue
                        val=struct.unpack_from('<Q',data,i)[0]
                        if not(min_t<=val<=max_t): continue
                        for t_addr,chain_to_hp in current_targets.items():
                            if abs(val-t_addr)>max_off: continue
                            off=t_addr-val
                            new_chain=[(ptr_addr,off)]+chain_to_hp
                            if is_module_addr(pm,ptr_addr) and mod_base:
                                offsets=[o for _,o in new_chain]
                                results.append({'rel_base':ptr_addr-mod_base,
                                                'offsets':offsets,'depth':depth+1})
                            elif ptr_addr not in next_targets:
                                next_targets[ptr_addr]=new_chain
                            seen_ptr_addrs.add(ptr_addr); break
                    n+=1
                    if progress_cb and n%30==0:
                        layer_pct=(depth+addr/SCAN_LIMIT)/max_depth
                        progress_cb(layer_pct, f"第{depth+1}層 鏈:{len(results)}")
                except: pass
            addr=next_addr
        current_targets=next_targets
    if progress_cb: progress_cb(1.0, f"完成 {len(results)} 條")
    return results

def find_char_anchor(pm, hp_addr, cur_hp):
    """
    在 HP 地址附近尋找 max_hp 錨點。
    max_hp 必須 > cur_hp 一定幅度（避免把護甲、其他小值誤認為 max_hp）。
    若 cur_hp 很高（接近滿血），改用「等於 cur_hp」也接受。
    返回 (offset, max_hp_value) 或 (None, None)
    """
    # 最小差距：至少比 cur_hp 大 20%，且不小於 5
    margin = max(5, cur_hp // 5)
    candidates = []
    for off in [4, 8, 12, 16, -4, 20, -8, 24, -12, 28, -16, 32, -20]:
        v = rdi(pm, hp_addr + off)
        if v is None: continue
        if v >= cur_hp + margin and 0 < v <= 9999:
            candidates.append((off, v))
    if not candidates:
        # 若加了 margin 找不到，寬鬆一點：只要 > cur_hp
        for off in [4, 8, 12, 16, -4, 20, -8, 24, -12, 28, -16, 32, -20]:
            v = rdi(pm, hp_addr + off)
            if v is not None and v > cur_hp and 0 < v <= 9999:
                candidates.append((off, v))
    if not candidates: return None, None
    # 挑最小的（即最接近 cur_hp 但仍大於 cur_hp+margin 的值，最像 max_hp）
    candidates.sort(key=lambda x: x[1])
    return candidates[0]

# ════════════════════════════════════════════════════════════════════
#  CharEntry — HP 角色
# ════════════════════════════════════════════════════════════════════
class CharEntry:
    def __init__(self, name, note=""):
        self.name=name; self.note=note
        self.candidates=[]; self.ptr_candidates=[]
        self.stable_ptr=None; self.ptr_chain=None
        self.locked=False; self.lock_val=None; self.job=None
        # HashLink 錨點：max_hp 用來跨重啟自動重定位
        self.max_hp=None; self.max_hp_off=None

    def get_addr(self, pm):
        if self.ptr_chain and pm:
            return resolve_ml_ptr(pm,self.ptr_chain)
        if self.stable_ptr and pm:
            sp=self.stable_ptr
            mod_base=get_module_base(pm)
            ptr_addr=(mod_base+sp['rel_base'] if sp.get('rel_base') is not None
                      else sp['ptr_addr'])
            return resolve_ptr(pm,ptr_addr,sp['offset'])
        if self.candidates: return self.candidates[0]
        return None

    def read_hp(self,pm):
        a=self.get_addr(pm); return rdi(pm,a) if a else None

    def write_hp(self,pm,v):
        a=self.get_addr(pm)
        if a: wdi(pm,a,v); return True
        return False

    def has_stable(self):
        return self.ptr_chain is not None or self.stable_ptr is not None

    def stable_label(self):
        if self.ptr_chain: return f"★{self.ptr_chain['depth']}"
        if self.stable_ptr: return "★"
        return "○"

    def to_dict(self):
        return {'name':self.name,'note':self.note,
                'stable_ptr':self.stable_ptr,'ptr_chain':self.ptr_chain,
                'locked':self.locked,'lock_val':self.lock_val,
                'max_hp':self.max_hp,'max_hp_off':self.max_hp_off}

    @classmethod
    def from_dict(cls,d):
        e=cls(d['name'],d.get('note',''))
        e.stable_ptr=d.get('stable_ptr'); e.ptr_chain=d.get('ptr_chain')
        e.locked=d.get('locked',False); e.lock_val=d.get('lock_val')
        e.max_hp=d.get('max_hp'); e.max_hp_off=d.get('max_hp_off')
        return e

# ════════════════════════════════════════════════════════════════════
#  StatEntry — 其他數值（金幣/負重/速度/移動/攻距）
# ════════════════════════════════════════════════════════════════════
class StatEntry:
    WRITE_TYPE={'gold':'gold','weight':'int','spd':'float','mv':'int','rng':'int'}

    def __init__(self,key):
        self.key=key; self.ptr_chain=None
        self.candidates=[]; self.locked=False; self.lock_val=None

    def get_addr(self,pm):
        if self.ptr_chain and pm: return resolve_ml_ptr(pm,self.ptr_chain)
        if self.candidates: return self.candidates[0]
        return None

    def write_value(self,pm,v):
        wt=self.WRITE_TYPE.get(self.key,'int')
        addrs=[]
        if self.ptr_chain and pm:
            a=resolve_ml_ptr(pm,self.ptr_chain)
            if a: addrs=[a]
        if not addrs: addrs=list(self.candidates)
        for a in addrs:
            if wt=='gold':
                wdu(pm,a,enc_gold(int(v))); wdi(pm,a+4,int(v))
            elif wt=='float': wdf(pm,a,float(v))
            else: wdi(pm,a,int(v))

    def has_stable(self): return self.ptr_chain is not None

    def to_dict(self):
        return {'key':self.key,'ptr_chain':self.ptr_chain,
                'locked':self.locked,'lock_val':self.lock_val}

    @classmethod
    def from_dict(cls,d):
        e=cls(d['key']); e.ptr_chain=d.get('ptr_chain')
        e.locked=d.get('locked',False); e.lock_val=d.get('lock_val')
        return e

# ════════════════════════════════════════════════════════════════════
BG="#1e1e2e"; BG2="#313244"; BG3="#181825"
FG="#cdd6f4"; ACC="#89b4fa"; GRN="#a6e3a1"
RED="#f38ba8"; YEL="#f9e2af"; GRAY="#6c7086"
LINE="#45475a"; PURPLE="#cba6f7"; TEAL="#94e2d5"

# ── LED 進度條 ────────────────────────────────────────────────────────
class LedBar(tk.Canvas):
    SEGS=28
    def __init__(self,parent,**kw):
        kw.setdefault('height',14); kw.setdefault('bg',BG)
        kw.setdefault('highlightthickness',0)
        super().__init__(parent,**kw)
        self._pct=0.0
        self.bind('<Configure>',self._redraw)

    def set(self,pct):
        self._pct=max(0.0,min(1.0,float(pct))); self._redraw()

    def reset(self):
        self._pct=0.0; self._redraw()

    def _redraw(self,*_):
        self.delete('all')
        w=self.winfo_width(); h=self.winfo_height()
        if w<4 or h<4: return
        n=self.SEGS; sw=w/n; lit=int(self._pct*n)
        for i in range(n):
            x0=int(i*sw)+1; x1=int((i+1)*sw)-1
            if i<lit:
                r=i/n
                col='#f38ba8' if r<0.33 else ('#f9e2af' if r<0.66 else '#a6e3a1')
            else:
                col='#2a2a3e'
            self.create_rectangle(x0,2,x1,h-2,fill=col,outline='')

# ════════════════════════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wartales Trainer  v10")
        self.configure(bg=BG); self.resizable(False,False)
        self._pm=None; self._scanning=False
        self._stop=threading.Event(); self._lock_jobs={}
        self._stats={k:StatEntry(k) for k in ('gold','weight','spd','mv','rng')}
        self._chars=[]; self._hp_pool=[]
        # 已儲存的 NOP Patch：[{'offset':int,'length':int,'orig_bytes':list,'label':str}]
        self._patches=[]
        self._rescan_running=False  # 防止 _rescan_chars_bg 重複執行
        self._build()
        self._load_data()
        self._attach()
        self._refresh_loop()

    # ── 連接 ──────────────────────────────────────────────────────────
    def _attach(self):
        try:
            if self._pm: self._pm.close_process()
        except: pass
        try:
            self._pm=pymem.Pymem("Wartales.exe")
            self.proc_v.set(f"✅ 已連接  PID:{self._pm.process_id}")
            self.proc_l.config(fg=GRN); self._st("連接成功",GRN)
            self._auto_resolve_all()
        except:
            self._pm=None
            self.proc_v.set("找不到 Wartales.exe")
            self.proc_l.config(fg=RED)

    def _chk(self):
        if not self._pm: self._attach()
        if not self._pm: messagebox.showwarning("未連接","請先啟動遊戲"); return False
        return True

    def _probe_char_anchor(self, char):
        """加入角色後立即探測 max_hp 錨點，存入 CharEntry 供跨重啟自動定位用"""
        if not self._pm or not char.candidates: return
        hp_addr=char.candidates[0]
        hp=rdi(self._pm,hp_addr)
        if hp is None or hp<=0: return
        off,val=find_char_anchor(self._pm,hp_addr,hp)
        if off is not None:
            char.max_hp=val; char.max_hp_off=off
            self._save_data()
            _log(f"ANCHOR OK  {char.name}  addr={hp_addr:#x}  cur_hp={hp}  max_hp={val}  off={off:+d}")
            self._st(f"{char.name}：錨點 max_hp={val}（偏移{off:+d}）✅",GRN)
        else:
            _log(f"ANCHOR FAIL  {char.name}  addr={hp_addr:#x}  cur_hp={hp}  (no candidate)")
            self._st(f"{char.name}：找不到 max_hp 錨點！建議在 HP 較高時加入清單",YEL)

    def _rescan_chars_bg(self, to_scan):
        """
        分層重掃：
          Tier1 先掃 _last_addr ±50MB（秒級完成）
          Tier2 才全掃（30-60秒，Tier1 沒找到才用）
        _rescan_running guard 防止同時觸發多次。
        """
        if self._rescan_running or not self._pm or not to_scan: return
        anchored=[(c,c.max_hp,c.max_hp_off) for c in to_scan
                  if c.max_hp and c.max_hp_off is not None]
        if not anchored:
            self._st("、".join(c.name for c in to_scan)+"：無錨點，請手動重掃HP",RED)
            return

        self._rescan_running=True
        self._st(f"重定位 {len(anchored)} 個角色...",TEAL)
        lookup={}
        for c,mhp,off in anchored:
            lookup.setdefault(mhp,[]).append((c,off))

        def scan_range(addr_from, addr_to, existing_found):
            found=dict(existing_found)
            allowed={S.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
                     S.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
                     S.MEMORY_PROTECTION.PAGE_READWRITE,
                     S.MEMORY_PROTECTION.PAGE_READONLY}
            addr=max(0,addr_from)
            while addr<min(addr_to,SCAN_LIMIT):
                if self._stop.is_set(): return found
                try: mbi=pymem.memory.virtual_query(self._pm.process_handle,addr)
                except: break
                next_addr=mbi.BaseAddress+mbi.RegionSize
                if (mbi.state==S.MEMORY_STATE.MEM_COMMIT and
                        mbi.protect in allowed and mbi.RegionSize>=4):
                    try:
                        size=mbi.RegionSize-(addr-mbi.BaseAddress)
                        data=pymem.memory.read_bytes(self._pm.process_handle,addr,size)
                        for i in range(0,len(data)-3,4):
                            v=struct.unpack_from('<i',data,i)[0]
                            if v not in lookup: continue
                            hit=addr+i
                            for c,off in lookup[v]:
                                if c.name in found: continue
                                hp_addr=hit-off
                                hp=rdi(self._pm,hp_addr)
                                if (hp is not None and 0<hp<=v and
                                        rdi(self._pm,hp_addr+off)==v):
                                    found[c.name]=hp_addr
                    except: pass
                addr=next_addr
            return found

        def worker():
            R=50*1024*1024  # ±50MB
            # Tier 1：只掃上次地址附近（快）
            hints=[getattr(c,'_last_addr',None) for c,_,_ in anchored]
            found={}
            for hint in set(h for h in hints if h):
                found=scan_range(hint-R, hint+R, found)
                self.after(0,lambda n=len(found):self._st(
                    f"快速重掃中... 已找 {n}/{len(anchored)} 個",TEAL))
                if len(found)==len(anchored): break

            # Tier 2：若有漏掉 → 全掃
            if len(found)<len(anchored):
                self.after(0,lambda:self._st("快速掃描未完全，執行全域掃描...",YEL))
                found=scan_range(0, SCAN_LIMIT, found)
            return found

        def on_done(result):
            self._rescan_running=False
            recovered=0
            for c,_,_ in anchored:
                if c.name in result:
                    new_addr=result[c.name]
                    _log(f"RESCAN_FOUND  {c.name}  new_addr={new_addr:#x}  max_hp={c.max_hp}  off={c.max_hp_off}")
                    c.candidates=[new_addr]; c._last_addr=new_addr
                    c._write_count=0; recovered+=1
                    if c.locked and c.lock_val is not None:
                        if c.job: self.after_cancel(c.job)
                        c.job=None; self._do_char_lock(c,c.lock_val)
                else:
                    _log(f"RESCAN_MISS  {c.name}  max_hp={c.max_hp}  off={c.max_hp_off}  last_addr={getattr(c,'_last_addr',None)}")
            self._refresh_char_list()
            if recovered==len(anchored):
                self._st(f"自動定位 {recovered} 個角色 ✅",GRN)
            else:
                failed=[c.name for c,_,_ in anchored if c.name not in result]
                self._st(f"定位 {recovered}/{len(anchored)}；{'/'.join(failed)} 需手動重掃",YEL)
            self.after(1500,self._led.reset)

        def _run():
            result=worker()
            self.after(0,lambda r=result:on_done(r))
        threading.Thread(target=_run,daemon=True).start()

    def _auto_resolve_all(self):
        """重連後用指標鏈還原所有位址並恢復鎖定"""
        if not self._pm: return
        hp_ok=0; hp_fail=[]
        for c in self._chars:
            c.candidates=[]
            if c.has_stable():
                addr=c.get_addr(self._pm)
                if addr is not None:
                    hp=rdi(self._pm,addr)
                    if hp is not None and 0<hp<999999:
                        c.candidates=[addr]; c._last_addr=addr; hp_ok+=1
            if not c.candidates: hp_fail.append(c.name)
            if c.locked and c.lock_val is not None and c.candidates:
                if c.job: self.after_cancel(c.job)
                c.job=None; self._do_char_lock(c,c.lock_val)

        st_ok=0; st_fail=[]
        for key,st in self._stats.items():
            st.candidates=[]
            if st.has_stable():
                addr=st.get_addr(self._pm)
                if addr is not None:
                    st_ok+=1
                    if st.locked and st.lock_val is not None:
                        if key in self._lock_jobs: self.after_cancel(self._lock_jobs.pop(key))
                        lv=getattr(self,f"_lock_{key}",None)
                        lb=getattr(self,f"_lockbtn_{key}",None)
                        if lv: lv.set(True)
                        if lb: lb.config(text="🔓 停止",bg=RED)
                        self._do_lock(key)
                        rv=getattr(self,f"_r_{key}",None)
                        if rv: rv.set(f"★ 已恢復鎖定 {st.lock_val}")
                else:
                    if st.locked: st_fail.append(key)
                    st.locked=False; st.lock_val=None
                    lv=getattr(self,f"_lock_{key}",None)
                    lb=getattr(self,f"_lockbtn_{key}",None)
                    if lv: lv.set(False)
                    if lb: lb.config(text="🔒 鎖定",bg=LINE)

        self._refresh_char_list()
        parts=[]
        if self._chars: parts.append(f"HP {hp_ok}/{len(self._chars)}" +
            (f" 【{'、'.join(hp_fail)}自動重掃中...】" if hp_fail else " ✅"))
        if any(st.has_stable() for st in self._stats.values()):
            parts.append(f"數值鎖定 {st_ok}個" +
                (f" 【{'、'.join(st_fail)}指標失效】" if st_fail else " ✅"))
        if parts: self._st("  ".join(parts), YEL if (hp_fail or st_fail) else GRN)

        # 指標鏈失效的角色 → 後台用 max_hp 錨點重定位
        fail_chars=[c for c in self._chars if not c.candidates]
        if fail_chars:
            self.after(500, lambda fc=fail_chars: self._rescan_chars_bg(fc))

        # 自動套用已儲存的 NOP Patch
        if self._patches:
            self.after(200, self._auto_apply_patches)

    def _auto_apply_patches(self):
        """連線後自動對所有已儲存的 NOP Patch 重新套用（exe 偏移固定，跨重啟有效）"""
        if not self._pm or not self._patches: return
        mod_base=get_module_base(self._pm)
        if not mod_base: return
        ok=0; skip=0; fail_list=[]
        for p in self._patches:
            addr=mod_base+p['offset']; n=p['length']
            try:
                cur=pymem.memory.read_bytes(self._pm.process_handle,addr,n)
                nops=b'\x90'*n
                if bytes(cur)==nops: ok+=1; continue   # 已是 NOP，跳過
                # 驗證原始位元組（防遊戲更新後 patch 到錯誤地方）
                orig=bytes(p.get('orig_bytes',[]))
                if orig and bytes(cur)!=orig:
                    fail_list.append(p['label']); continue
                apply_nop_patch(self._pm.process_handle,addr,n)
                ok+=1
            except: fail_list.append(p['label'])
        self._refresh_patch_list()
        if fail_list:
            self._st(f"Patch: {ok} 成功，{len(fail_list)} 失效（遊戲版本可能更新）",YEL)
        elif ok:
            self._st(f"自動套用 {ok} 個 NOP Patch ✅",GRN)

    # ── 背景掃描 ───────────────────────────────────────────────────────
    def _bg(self,fn,on_done,status_v=None,btn=None,restore_cmd=None):
        if self._scanning: messagebox.showwarning("提示","掃描中"); return
        self._scanning=True; self._stop.clear(); self._led.reset()
        if btn: btn.config(text="⏹ 停止",bg=RED,command=lambda:self._stop.set())
        if status_v: status_v.set("掃描中...")
        def worker():
            r=fn()
            self.after(0,lambda:self._bg_done(r,on_done,status_v,btn,restore_cmd))
        threading.Thread(target=worker,daemon=True).start()

    def _bg_done(self,r,on_done,status_v,btn,restore_cmd=None):
        self._scanning=False; self._led.set(1.0)
        if btn:
            kw=dict(text="🔍 掃描",bg=ACC)
            if restore_cmd: kw['command']=restore_cmd
            btn.config(**kw)
        on_done(r)
        self.after(1500,self._led.reset)

    def _led_cb(self,pct,*_):
        self.after(0,lambda p=pct:self._led.set(p))

    def _refresh_loop(self):
        try: self._refresh_char_list()
        except: pass
        # 偵測鎖定角色地址失效（新戰鬥換了記憶體位址） → 自動觸發重掃
        try: self._check_and_rescan_locked()
        except: pass
        self.after(1000,self._refresh_loop)

    def _check_and_rescan_locked(self):
        """每秒檢查：鎖定中但地址已失效 → 觸發重掃（有 _rescan_running guard）"""
        if not self._pm or self._rescan_running: return
        need=[c for c in self._chars
              if c.locked and not c.candidates and c.max_hp]
        if need:
            names="、".join(c.name for c in need)
            _log(f"RESCAN_TRIGGER  chars={names}")
            self._st(f"⚠ 偵測到 {names} 地址失效（換場？），自動重掃中...",YEL)
            self._pulse_ph=0
            self.after(20,self._pulse_led)
            self._rescan_chars_bg(need)
        elif any(c.locked and c.candidates for c in self._chars):
            # 全部鎖定且有效 → 顯示 ✅
            locked_ok=sum(1 for c in self._chars if c.locked and c.candidates)
            self._stl.config(fg=GRN if self._stv.get().startswith("⚠") else GRAY)

    # ── UI ─────────────────────────────────────────────────────────────
    def _build(self):
        hdr=tk.Frame(self,bg=BG3,pady=10); hdr.pack(fill="x")
        tk.Label(hdr,text="⚔  Wartales Trainer",
                 font=("Segoe UI",16,"bold"),bg=BG3,fg=ACC).pack()
        tk.Label(hdr,text="v10 — 鎖定後重啟自動恢復，LED 進度條",
                 font=("Segoe UI",10),bg=BG3,fg=GRAY).pack()

        pr=tk.Frame(self,bg=BG,pady=5); pr.pack(fill="x",padx=14)
        tk.Label(pr,text="狀態：",bg=BG,fg=FG,font=("Segoe UI",11)).pack(side="left")
        self.proc_v=tk.StringVar(value="未連接")
        self.proc_l=tk.Label(pr,textvariable=self.proc_v,bg=BG,fg=RED,
                              font=("Segoe UI",11,"bold"))
        self.proc_l.pack(side="left")
        self._mb(pr,"🔌 重連",self._attach,ACC,8).pack(side="right")
        tk.Frame(self,bg=LINE,height=1).pack(fill="x",padx=14)

        nb=tk.Frame(self,bg=BG); nb.pack(fill="both",expand=True,padx=14,pady=6)
        self._tabs=[]; self._tbns=[]
        bar=tk.Frame(nb,bg=BG); bar.pack(fill="x")
        cont=tk.Frame(nb,bg=BG2,highlightthickness=1,highlightbackground=LINE)
        cont.pack(fill="both",expand=True)
        for i,(lbl,fn) in enumerate([
            ("❤️ HP",self._pg_hp),("🪙 金幣",self._pg_gold),
            ("🎒 負重",self._pg_weight),("⚡ 移動",self._pg_move),
            ("🎯 攻距",self._pg_range)]):
            f=tk.Frame(cont,bg=BG2); self._tabs.append(f); fn(f)
            b=tk.Button(bar,text=lbl,bg=BG2 if i==0 else BG,fg=FG,
                        font=("Segoe UI",10,"bold"),relief="flat",
                        padx=10,pady=5,cursor="hand2",bd=0,
                        activebackground=BG2,activeforeground=ACC,
                        command=lambda i=i:self._sw(i))
            b.pack(side="left"); self._tbns.append(b)
        self._sw(0)
        tk.Frame(self,bg=LINE,height=1).pack(fill="x",padx=14)

        # LED 進度條列
        led_fr=tk.Frame(self,bg=BG); led_fr.pack(fill="x",padx=14,pady=(4,0))
        tk.Label(led_fr,text="掃描",bg=BG,fg=GRAY,
                 font=("Segoe UI",8)).pack(side="left",padx=(0,4))
        self._led=LedBar(led_fr)
        self._led.pack(side="left",fill="x",expand=True)

        self._stv=tk.StringVar(value="就緒")
        self._stl=tk.Label(self,textvariable=self._stv,bg=BG,fg=GRAY,
                            font=("Segoe UI",10),anchor="w")
        self._stl.pack(fill="x",padx=14,pady=(2,5))

    def _sw(self,idx):
        for f in self._tabs: f.pack_forget()
        self._tabs[idx].pack(fill="both",expand=True,padx=8,pady=8)
        for i,b in enumerate(self._tbns):
            b.config(bg=BG2 if i==idx else BG,fg=ACC if i==idx else FG)

    def _mb(self,p,t,c,col,w=8):
        return tk.Button(p,text=t,command=c,bg=col,fg=BG3,
                         font=("Segoe UI",10,"bold"),relief="flat",
                         padx=6,pady=4,cursor="hand2",width=w,
                         activebackground=col,activeforeground=BG3)

    def _st(self,msg,col=None):
        self._stv.set(msg); self._stl.config(fg=col or GRAY)

    # ── HP 頁面 ────────────────────────────────────────────────────────
    def _pg_hp(self,p):
        tk.Label(p,
            text="【首次設定】掃描→縮小→加入清單→程式自動學習指標\n"
                 "【之後重開遊戲】直接連線，程式自動恢復所有角色",
            bg=BG2,fg=FG,font=("Segoe UI",10),
            justify="left",wraplength=430).pack(anchor="w",padx=8,pady=(6,2))

        sr=tk.Frame(p,bg=BG2); sr.pack(fill="x",padx=6,pady=3)
        tk.Label(sr,text="HP：",bg=BG2,fg=FG,font=("Segoe UI",11)).pack(side="left")
        self._v_hp=tk.StringVar(value="100")
        tk.Entry(sr,textvariable=self._v_hp,bg=BG,fg=FG,insertbackground=FG,
                 font=("Consolas",12),width=8,relief="flat",
                 highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC
                 ).pack(side="left",ipady=3,padx=4)
        self._btn_hp1=self._mb(sr,"🔍 掃描",self._hp_first,ACC,7)
        self._btn_hp1.pack(side="left",padx=2)
        self._mb(sr,"🔍 縮小",self._hp_narrow,YEL,6).pack(side="left",padx=2)
        self._mb(sr,"🗑 清除",self._hp_clear,LINE,6).pack(side="left",padx=2)

        self._hp_pool_v=tk.StringVar(value="尚未掃描")
        tk.Label(p,textvariable=self._hp_pool_v,
                 bg=BG2,fg=GRAY,font=("Segoe UI",9),anchor="w").pack(fill="x",padx=8)

        pf=tk.Frame(p,bg=BG2); pf.pack(fill="x",padx=6)
        sb=tk.Scrollbar(pf,bg=BG2,troughcolor=BG2); sb.pack(side="right",fill="y")
        self._pool_lb=tk.Listbox(pf,bg=BG,fg=FG,font=("Consolas",10),height=3,
                                  relief="flat",selectmode="extended",
                                  highlightthickness=1,highlightbackground=LINE,
                                  selectbackground=PURPLE,selectforeground=BG3,
                                  yscrollcommand=sb.set)
        self._pool_lb.pack(side="left",fill="x",expand=True)
        sb.config(command=self._pool_lb.yview)

        ar=tk.Frame(p,bg=BG2); ar.pack(fill="x",padx=6,pady=2)
        self._mb(ar,"➕ 加入角色清單",self._add_char,PURPLE,14).pack(side="left")
        self._mb(ar,"🔄 更新位址",self._update_char_addr,TEAL,10).pack(side="left",padx=4)
        self._mb(ar,"👂 監聽寫入",self._start_watch_hp,YEL,9).pack(side="left",padx=2)
        tk.Label(ar,text="← 選候選位址後點監聽，讓角色被打",
                 bg=BG2,fg=GRAY,font=("Segoe UI",9)).pack(side="left",padx=4)

        tk.Frame(p,bg=LINE,height=1).pack(fill="x",padx=6,pady=3)

        hdr2=tk.Frame(p,bg=BG2); hdr2.pack(fill="x",padx=6)
        tk.Label(hdr2,text="角色清單",bg=BG2,fg=GRN,
                 font=("Segoe UI",11,"bold")).pack(side="left")
        tk.Label(hdr2,text="（★=已學習指標，重啟自動恢復）",
                 bg=BG2,fg=TEAL,font=("Segoe UI",9)).pack(side="left",padx=6)

        cf=tk.Frame(p,bg=BG2); cf.pack(fill="x",padx=6)
        sb2=tk.Scrollbar(cf,bg=BG2,troughcolor=BG2); sb2.pack(side="right",fill="y")
        self._char_lb=tk.Listbox(cf,bg=BG,fg=FG,font=("Consolas",11),height=5,
                                  relief="flat",selectmode="extended",
                                  highlightthickness=1,highlightbackground=LINE,
                                  selectbackground=GRN,selectforeground=BG3,
                                  yscrollcommand=sb2.set)
        self._char_lb.pack(side="left",fill="x",expand=True)
        sb2.config(command=self._char_lb.yview)
        self._char_lb.bind("<Double-Button-1>",self._char_edit)

        cr=tk.Frame(p,bg=BG2); cr.pack(fill="x",padx=6,pady=3)
        tk.Label(cr,text="HP值：",bg=BG2,fg=FG,font=("Segoe UI",11)).pack(side="left")
        self._v_hp_w=tk.StringVar(value="9999")
        tk.Entry(cr,textvariable=self._v_hp_w,bg=BG,fg=FG,insertbackground=FG,
                 font=("Consolas",12),width=7,relief="flat",
                 highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC
                 ).pack(side="left",ipady=3,padx=4)
        for sv,st in [(9999,"9999"),(99999,"99999")]:
            tk.Button(cr,text=st,bg=LINE,fg=FG,font=("Segoe UI",9),
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
                 bg=BG2,fg=GRAY,font=("Segoe UI",9)).pack(anchor="w",padx=8)

        # ── 自動 NOP Patch 清單 ──────────────────────────────────────────
        tk.Frame(p,bg=LINE,height=1).pack(fill="x",padx=6,pady=(6,2))
        ph2=tk.Frame(p,bg=BG2); ph2.pack(fill="x",padx=6)
        tk.Label(ph2,text="⚡ 自動 NOP Patch",bg=BG2,fg=RED,
                 font=("Segoe UI",10,"bold")).pack(side="left")
        tk.Label(ph2,text="（每次連線自動套用）",bg=BG2,fg=GRAY,
                 font=("Segoe UI",9)).pack(side="left",padx=4)
        self._mb(ph2,"🗑 清除全部",self._clear_patches,LINE,8).pack(side="right")

        plf=tk.Frame(p,bg=BG2); plf.pack(fill="x",padx=6,pady=(0,4))
        psb=tk.Scrollbar(plf,bg=BG2,troughcolor=BG2); psb.pack(side="right",fill="y")
        self._patch_lb=tk.Listbox(plf,bg=BG,fg=FG,font=("Consolas",9),height=2,
                                   relief="flat",selectmode="single",
                                   highlightthickness=1,highlightbackground=LINE,
                                   selectbackground=RED,selectforeground=BG3,
                                   yscrollcommand=psb.set)
        self._patch_lb.pack(side="left",fill="x",expand=True)
        psb.config(command=self._patch_lb.yview)
        self._patch_lb.insert("end","  （尚無已儲存 Patch）")

    # ── HP 掃描 ────────────────────────────────────────────────────────
    def _hp_first(self):
        if not self._chk(): return
        try: v=int(self._v_hp.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        vb=struct.pack('<i',v)
        def do(): return scan_value(self._pm,vb,self._stop,self._led_cb)
        def done(r):
            self._hp_pool=r; self._refresh_pool()
            self._hp_pool_v.set(f"找到 {len(r)} 個  →  讓HP改變後按縮小")
            self._btn_hp1.config(text="🔍 掃描",bg=ACC,command=self._hp_first)
        self._btn_hp1.config(text="⏹ 停止",bg=RED,command=lambda:self._stop.set())
        self._bg(do,done,self._hp_pool_v,self._btn_hp1,restore_cmd=self._hp_first)

    def _hp_narrow(self):
        if not self._chk(): return
        if not self._hp_pool: messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_hp.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        vb=struct.pack('<i',v)
        self._hp_pool=narrow_scan(self._pm,self._hp_pool,vb)
        self._refresh_pool()
        n=len(self._hp_pool)
        self._hp_pool_v.set(f"縮小後剩 {n} 個{'  →  繼續縮小' if n>5 else '  →  可加入清單了'}")
        self._st(f"縮小後剩 {n} 個",GRN if n else RED)

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
            self._pool_lb.insert("end",f"  ... 共{len(self._hp_pool)}筆")

    # ── 角色管理 ───────────────────────────────────────────────────────
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
            c=CharEntry(r[0],r[1]); c.candidates=[addr]
            self._chars.append(c); added+=1
            self._probe_char_anchor(c)   # 立即探測 max_hp，供跨重啟定位
            self._bg_learn_ptr(c)
        self._refresh_char_list(); self._refresh_pool()
        if added: self._st(f"加入 {added} 個角色，開始學習指標...",TEAL)

    def _update_char_addr(self):
        if not self._chk(): return
        pool_sel=self._pool_lb.curselection(); char_sel=self._char_sel()
        if not pool_sel: messagebox.showwarning("提示","請先在候選池選取新的 HP 位址"); return
        if not char_sel: messagebox.showwarning("提示","請先在角色清單選取要更新的角色"); return
        if len(pool_sel)!=len(char_sel):
            messagebox.showwarning("提示",f"候選池選了 {len(pool_sel)} 個，角色選了 {len(char_sel)} 個，數量需相同")
            return
        for idx,c in zip(pool_sel,char_sel):
            if idx>=len(self._hp_pool): continue
            new_addr=self._hp_pool[idx]
            if c.job: self.after_cancel(c.job); c.job=None
            c.candidates=[new_addr]; c.stable_ptr=None; c.ptr_chain=None
            c.max_hp=None; c.max_hp_off=None   # 重置錨點，重新探測
            if c.locked and c.lock_val is not None: self._do_char_lock(c,c.lock_val)
            self._probe_char_anchor(c)
            self._bg_learn_ptr(c)
        self._save_data(); self._refresh_char_list(); self._refresh_pool()
        names="、".join(c.name for c in char_sel)
        self._st(f"{names}：位址已更新，重新學習指標中...",TEAL)

    def _bg_learn_ptr(self,char):
        """單層失敗後自動升級多層"""
        if not self._pm or not char.candidates: return
        target=char.candidates[0]
        self._st(f"正在學習 {char.name} 的指標（單層）...",TEAL)
        def do(): return pointer_scan(self._pm,target,max_off=0x800,
                                      stop_evt=self._stop,progress_cb=self._led_cb)
        def done(results):
            char.ptr_candidates=results; self._try_stabilize(char)
            if not char.stable_ptr:
                self._st(f"{char.name}：單層無靜態指標，自動啟動多層掃描...",YEL)
                self._start_ml_scan(char)
        self._bg(do,done)

    def _start_ml_scan(self,char):
        if not self._pm or not char.candidates: return
        target=char.candidates[0]
        def do(tgt=target):
            return multilevel_ptr_scan(self._pm,tgt,max_depth=3,
                                       max_off=0x800,stop_evt=self._stop,
                                       progress_cb=self._led_cb)
        def done(results,c=char):
            self._st(f"{c.name}：多層完成，找到 {len(results)} 條候選鏈",
                     GRN if results else YEL)
            self._try_stabilize_ml(c,results)
            if not c.has_stable():
                self._st(f"{c.name}：無法學習穩定指標，重啟後需重新掃描",RED)
        self._bg(do,done)

    def _try_stabilize(self,char):
        if not self._pm or not char.ptr_candidates or not char.candidates: return
        known=char.candidates[0]; mod_base=get_module_base(self._pm) or 0
        static_set=set(pa for pa,off in char.ptr_candidates if is_module_addr(self._pm,pa))
        cands=[(pa,off) for pa,off in char.ptr_candidates if pa in static_set] or char.ptr_candidates
        valid=[]
        for pa,off in cands[:2000]:
            tgt=resolve_ptr(self._pm,pa,off)
            if tgt!=known: continue
            is_s=pa in static_set
            rel=pa-mod_base if(is_s and mod_base) else None
            valid.append({'ptr_addr':pa,'offset':off,'rel_base':rel,'is_static':is_s})
        if valid:
            s=[v for v in valid if v['is_static']]
            char.stable_ptr=(s or valid)[0]
            self._save_data(); self._refresh_char_list()
            self._st(f"{char.name}：單層{'靜態' if s else '動態'}指標學習成功",
                     GRN if s else YEL)
        else:
            self._st(f"{char.name}：單層無靜態指標，請點「多層掃描」",YEL)

    def _try_stabilize_ml(self,char,ml_results):
        if not self._pm or not ml_results or not char.candidates: return
        known=char.candidates[0]
        valid=[r for r in ml_results if resolve_ml_ptr(self._pm,r)==known]
        if valid:
            valid.sort(key=lambda r:r['depth'])
            char.ptr_chain=valid[0]; self._save_data(); self._refresh_char_list()
            self._st(f"{char.name}：{valid[0]['depth']} 層指標鏈學習成功！重啟自動恢復",GRN)
        else:
            self._st(f"{char.name}：多層掃描未找到有效鏈，請先縮小 HP 候選再掃",YEL)

    def _refresh_char_list(self):
        try:
            sel=list(self._char_lb.curselection())
            self._char_lb.delete(0,"end")
            for c in self._chars:
                hp=c.read_hp(self._pm) if self._pm else None
                lock="🔒" if c.locked else "  "
                star=c.stable_label()
                note=f"  [{c.note}]" if c.note else ""
                hp_s=str(hp) if hp is not None else "?"
                self._char_lb.insert("end",f" {lock}{star} {c.name:<14} HP={hp_s:<6}{note}")
            for i in sel:
                if i<self._char_lb.size(): self._char_lb.selection_set(i)
        except: pass

    def _char_edit(self,_=None):
        sel=self._char_lb.curselection()
        if not sel: return
        c=self._chars[sel[0]]; r=self._name_dlg(c.name,c.note)
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
        self._refresh_char_list(); self._st(f"HP={v} 寫入 {ok}/{len(t)} 個角色",GRN)

    def _char_lock(self):
        if not self._chk(): return
        t=self._char_sel()
        if not t: messagebox.showwarning("提示","請先選取角色"); return
        try: v=int(self._v_hp_w.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        for c in t:
            if c.locked: continue
            c.locked=True; c.lock_val=v; self._do_char_lock(c,v)
        self._save_data(); self._refresh_char_list()
        self._st(f"鎖定 HP={v}",RED)

    def _do_char_lock(self,char,val):
        if not char.locked or not self._pm: return
        hp=char.read_hp(self._pm)
        if hp is not None and 0<hp<999999:
            char.write_hp(self._pm,val)
            a=char.get_addr(self._pm)
            if a: char._last_addr=a
            char._addr_fail_count=0
            char._write_count=getattr(char,'_write_count',0)+1
            if char._write_count>50 and hp < val//2:
                _log(f"STALE addr={a:#x}  hp={hp}  lock_val={val}  write_count={char._write_count} → 清空候選")
                char.candidates=[]; char._write_count=0
        else:
            cnt=getattr(char,'_addr_fail_count',0)+1
            char._addr_fail_count=cnt; char._write_count=0
            if cnt>=5:
                a=char.get_addr(self._pm)
                _log(f"FAIL×5 addr={a}  hp={hp} → 清空候選")
                char.candidates=[]; char._addr_fail_count=0
        char.job=self.after(20,lambda:self._do_char_lock(char,val))

    def _char_unlock(self):
        for c in (self._char_sel() or self._chars):
            if c.job: self.after_cancel(c.job)
            c.locked=False; c.job=None
        self._save_data(); self._refresh_char_list(); self._st("已解鎖",GRAY)

    def _char_remove(self):
        sel=self._char_lb.curselection()
        if not sel: return
        for i in sorted(sel,reverse=True):
            c=self._chars[i]
            if c.job: self.after_cancel(c.job)
            del self._chars[i]
        self._refresh_char_list(); self._save_data()

    def _char_ml_scan(self):
        if not self._chk(): return
        t=self._char_sel()
        if not t: messagebox.showwarning("提示","請先在角色清單選取角色"); return
        for c in t:
            if not c.candidates:
                if self._hp_pool and len(self._hp_pool)<=5:
                    c.candidates=[self._hp_pool[0]]
                    self._st(f"{c.name}：自動借用候選池位址 {self._hp_pool[0]:#x}",TEAL)
                else:
                    self._st(f"{c.name} 無 HP 位址，請先掃描並縮小候選",RED); continue
            self._st(f"正在多層掃描 {c.name}（最多3層）...",TEAL)
            self._start_ml_scan(c); break

    # ── 監聽 HP 寫入 ────────────────────────────────────────────────────
    def _pulse_led(self):
        """監聽期間 LED 脈衝動畫（掃描進行中時持續跳動）"""
        if not self._scanning: return
        import math
        self._pulse_ph=getattr(self,'_pulse_ph',0)+0.06
        self._led.set(0.5+0.45*math.sin(self._pulse_ph))
        self.after(40,self._pulse_led)

    def _start_watch_hp(self):
        """設置硬體中斷點，監聽選取的候選位址被誰寫入（無固定超時，⏹ 停止取消）"""
        if not self._chk(): return
        sel=self._pool_lb.curselection()
        if not sel:
            messagebox.showwarning("提示","請先在候選池選取一個 HP 位址"); return
        idx=sel[0]
        if idx>=len(self._hp_pool):
            messagebox.showwarning("提示","選取的位址無效，請重新掃描"); return
        addr=self._hp_pool[idx]
        hp=rdi(self._pm,addr)
        mod_base=get_module_base(self._pm) or 0

        self._st(f"監聽 {addr:#x}（HP={hp}）— 讓角色被打，或按 ⏹ 停止",YEL)
        self._pulse_ph=0
        self.after(50,self._pulse_led)  # 啟動 LED 脈衝動畫

        pid=self._pm.process_id
        ph=self._pm.process_handle

        def do():
            def cb(n):
                self.after(0,lambda:self._st(
                    f"監聽 {addr:#x} — 已找到 {n} 個寫入點，繼續讓角色受傷或按 ⏹ 停止",YEL))
            return watch_hp_write(pid,addr,ph,mod_base,
                                  stop_evt=self._stop,timeout=None,progress_cb=cb)
        def done(r):
            if isinstance(r,dict) and 'error' in r:
                self._st(f"監聽失敗：{r['error']}",RED); return
            if not r:
                self._st("監聽結束，未偵測到任何 HP 寫入",GRAY); return
            self._st(f"監聽結束：共找到 {len(r)} 個寫入點",GRN)
            self.after(50,lambda:self._show_aob_results(r))

        self._bg(do,done,btn=self._btn_hp1,restore_cmd=self._hp_first)

    def _show_aob_results(self, results):
        """顯示所有找到的 HP 寫入指令，可全選或個別 NOP Patch"""
        win=tk.Toplevel(self); win.title(f"找到 {len(results)} 個 HP 寫入路徑")
        win.configure(bg=BG); win.resizable(False,False); win.grab_set()
        win.geometry(f"+{self.winfo_x()+40}+{self.winfo_y()+60}")

        tk.Label(win,
            text=f"⚠️  找到 {len(results)} 個 HP 寫入路徑\n需全部 Patch 才能完全鎖血",
            bg=BG,fg=YEL,font=("Segoe UI",12,"bold"),justify="center").pack(pady=(14,6))

        # 清單：每列一個寫入點，含 checkbox
        frame=tk.Frame(win,bg=BG); frame.pack(fill="x",padx=16,pady=4)
        checks=[]
        for i,r in enumerate(results):
            moff=r['module_offset']; ibytes=r['instr_bytes']
            hex_b=' '.join(f'{b:02X}' for b in ibytes)
            already=any(p['offset']==moff for p in self._patches)
            v=tk.BooleanVar(value=not already)
            checks.append((v,r))
            row=tk.Frame(frame,bg=BG2,pady=3); row.pack(fill="x",pady=1)
            tk.Checkbutton(row,variable=v,bg=BG2,activebackground=BG2,
                           fg=FG,selectcolor=BG).pack(side="left",padx=4)
            lbl=f"{'✅ 已儲存' if already else f'#{i+1}'}   exe+{moff:#x}   {hex_b}"
            tk.Label(row,text=lbl,bg=BG2,
                     fg=GRAY if already else FG,
                     font=("Consolas",10)).pack(side="left")

        tk.Label(win,
            text="⚠️  HP 不適合 NOP — 新戰鬥初始化也會被擋，角色從 0 HP 開始。\n"
                 "HP 請用「🔒 鎖定」。此功能適合移動格/攻距等固定值。",
            bg=BG,fg=YEL,font=("Segoe UI",9),wraplength=420,justify="left"
            ).pack(padx=16,pady=(4,6))

        def do_patch_selected():
            patched=0; errors=[]
            for v,r in checks:
                if not v.get(): continue
                iaddr=r['instr_addr']; ibytes=r['instr_bytes']; moff=r['module_offset']
                try:
                    orig=apply_nop_patch(self._pm.process_handle,iaddr,len(ibytes))
                    if not any(p['offset']==moff for p in self._patches):
                        self._patches.append({
                            'offset':     moff,
                            'length':     len(ibytes),
                            'orig_bytes': list(orig),
                            'label':      f"HP寫入  exe+{moff:#x}  [{len(ibytes)}B]",
                        })
                    patched+=1
                except Exception as e:
                    errors.append(f"exe+{moff:#x}: {e}")
            if patched:
                self._save_data(); self._refresh_patch_list()
                self._st(f"已 Patch {patched} 條路徑並儲存 ✅",GRN)
            if errors:
                messagebox.showerror("部分 Patch 失敗",'\n'.join(errors))
            win.destroy()

        def sel_all():
            for v,r in checks:
                if not any(p['offset']==r['module_offset'] for p in self._patches):
                    v.set(True)

        bf=tk.Frame(win,bg=BG); bf.pack(pady=(4,14))
        self._mb(bf,"☑ 全選",sel_all,LINE,6).pack(side="left",padx=4)
        self._mb(bf,"⚡ Patch 勾選項目",do_patch_selected,RED,14).pack(side="left",padx=4)
        self._mb(bf,"關閉",win.destroy,LINE,6).pack(side="left",padx=4)

    # ── 對話框 ─────────────────────────────────────────────────────────
    def _name_dlg(self,name="",note=""):
        win=tk.Toplevel(self); win.title("角色名稱")
        win.configure(bg=BG); win.resizable(False,False); win.grab_set()
        win.geometry("+%d+%d"%(self.winfo_x()+80,self.winfo_y()+130))
        tk.Label(win,text="角色名稱：",bg=BG,fg=FG,font=("Segoe UI",11)
                 ).pack(padx=14,pady=(12,2),anchor="w")
        vn=tk.StringVar(value=name)
        en=tk.Entry(win,textvariable=vn,bg=BG2,fg=FG,insertbackground=FG,
                    font=("Segoe UI",12),width=18,relief="flat",
                    highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC)
        en.pack(padx=14,pady=(2,6),ipady=4); en.focus(); en.select_range(0,"end")
        tk.Label(win,text="附註（可留空）：",bg=BG,fg=FG,font=("Segoe UI",11)
                 ).pack(padx=14,anchor="w")
        vt=tk.StringVar(value=note)
        tk.Entry(win,textvariable=vt,bg=BG2,fg=FG,insertbackground=FG,
                 font=("Segoe UI",11),width=18,relief="flat",
                 highlightthickness=1,highlightbackground=LINE,highlightcolor=ACC
                 ).pack(padx=14,pady=(2,10),ipady=4)
        result=[None]
        def ok(): result[0]=(vn.get().strip() or name,vt.get().strip()); win.destroy()
        en.bind("<Return>",lambda _:ok())
        br=tk.Frame(win,bg=BG); br.pack(pady=(0,10))
        self._mb(br,"確定",ok,GRN,6).pack(side="left",padx=6)
        self._mb(br,"取消",win.destroy,LINE,6).pack(side="left",padx=6)
        win.wait_window(); return result[0]

    # ── 資料存取 ───────────────────────────────────────────────────────
    def _refresh_patch_list(self):
        try:
            self._patch_lb.delete(0,"end")
            if not self._patches:
                self._patch_lb.insert("end","  （尚無已儲存 Patch）"); return
            mod_base=get_module_base(self._pm) if self._pm else 0
            for p in self._patches:
                status="✅"
                if mod_base:
                    try:
                        cur=pymem.memory.read_bytes(self._pm.process_handle,
                                                    mod_base+p['offset'],p['length'])
                        status="✅" if bytes(cur)==b'\x90'*p['length'] else "⚠️"
                    except: status="?"
                self._patch_lb.insert("end",f"  {status}  {p['label']}")
        except: pass

    def _clear_patches(self):
        if not self._patches: return
        if messagebox.askyesno("清除 Patch","確定要移除所有已儲存的 NOP Patch？\n（不會恢復遊戲記憶體）"):
            self._patches=[]
            self._save_data(); self._refresh_patch_list()
            self._st("已清除所有 Patch 記錄",GRAY)

    def _save_data(self):
        try:
            data={
                'chars':[c.to_dict() for c in self._chars],
                'stats':{k:st.to_dict() for k,st in self._stats.items()
                         if st.has_stable() or st.locked},
                'patches':self._patches,
            }
            with open(DATA_FILE,'w',encoding='utf-8') as f:
                json.dump(data,f,ensure_ascii=False,indent=2)
        except: pass

    def _load_data(self):
        try:
            if not os.path.exists(DATA_FILE): return
            with open(DATA_FILE,encoding='utf-8') as f: raw=json.load(f)
            if isinstance(raw,list): chars_data=raw; stats_data={}; patches=[]
            else:
                chars_data=raw.get('chars',[]); stats_data=raw.get('stats',{})
                patches=raw.get('patches',[])
            self._chars=[CharEntry.from_dict(d) for d in chars_data]
            for k,d in stats_data.items():
                if k in self._stats: self._stats[k]=StatEntry.from_dict(d)
            self._patches=patches
            self._refresh_char_list()
            self._refresh_patch_list()
            n=len(self._chars); stable=sum(1 for c in self._chars if c.has_stable())
            stat_locked=sum(1 for st in self._stats.values() if st.locked)
            parts=[f"HP: {n} 個（{stable} 有指標）"]
            if stat_locked: parts.append(f"數值鎖定: {stat_locked} 個")
            if patches: parts.append(f"Patch: {len(patches)} 個")
            self._st("  ".join(parts),TEAL)
        except: pass

    # ── 其他數值頁面 ───────────────────────────────────────────────────
    def _simple_pg(self,p,key,title,hint,scan_fn,write_fn,
                   default,shortcuts=None,lock=False):
        tk.Label(p,text=title,bg=BG2,fg=ACC,
                 font=("Segoe UI",12,"bold")).pack(anchor="w",padx=6,pady=(8,2))
        tk.Label(p,text=hint,bg=BG2,fg=FG,font=("Segoe UI",10),
                 justify="left",wraplength=420).pack(anchor="w",padx=8)
        setattr(self,f"_v_{key}",tk.StringVar(value=default))
        r=tk.Frame(p,bg=BG2); r.pack(fill="x",padx=6,pady=4)
        tk.Entry(r,textvariable=getattr(self,f"_v_{key}"),
                 bg=BG,fg=FG,insertbackground=FG,font=("Consolas",13),width=12,
                 relief="flat",highlightthickness=1,
                 highlightbackground=LINE,highlightcolor=ACC
                 ).pack(side="left",ipady=4,padx=(0,4))
        if shortcuts:
            for sv,st in shortcuts:
                tk.Button(r,text=st,bg=LINE,fg=FG,font=("Segoe UI",10),
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
                         font=("Segoe UI",10,"bold"),relief="flat",
                         padx=6,pady=4,cursor="hand2",width=7,
                         command=lambda k=key:self._toggle_lock(k))
            lb.pack(side="left",padx=2)
            setattr(self,f"_lockbtn_{key}",lb)
        rv=tk.StringVar(value="尚未掃描（★=已學習指標，可跨啟動恢復）")
        setattr(self,f"_r_{key}",rv)
        tk.Label(p,textvariable=rv,bg=BG2,fg=GRAY,
                 font=("Segoe UI",9),anchor="w").pack(fill="x",padx=8)

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
        st=self._stats[key]
        var=getattr(self,f"_lock_{key}"); btn=getattr(self,f"_lockbtn_{key}")
        if var.get():
            var.set(False); btn.config(text="🔒 鎖定",bg=LINE)
            if key in self._lock_jobs: self.after_cancel(self._lock_jobs.pop(key))
            st.locked=False; st.lock_val=None; self._save_data()
        else:
            if not st.candidates and not st.has_stable():
                messagebox.showwarning("提示","請先掃描"); return
            try: lv=float(getattr(self,f"_v_{key}").get())
            except: messagebox.showerror("錯誤","請輸入有效數值"); return
            var.set(True); btn.config(text="🔓 停止",bg=RED)
            st.locked=True; st.lock_val=lv; self._save_data()
            self._do_lock(key)

    def _do_lock(self,key):
        st=self._stats[key]
        lv=getattr(self,f"_lock_{key}",None)
        if lv is None or not lv.get(): return
        if self._pm and st.lock_val is not None:
            st.write_value(self._pm,st.lock_val)
        self._lock_jobs[key]=self.after(150,lambda:self._do_lock(key))

    def _set_res(self,key,addrs):
        rv=getattr(self,f"_r_{key}"); n=len(addrs)
        st=self._stats[key]; star=" ★" if st.has_stable() else ""
        if n==0: rv.set("❌ 找不到"); self._st("掃描無結果",RED)
        elif n>2000: rv.set(f"⚠ 太多({n})，輸入更精確的值")
        else:
            s=" ".join(f"{a:#x}" for a in addrs[:3])
            rv.set(f"✅ {n}個{star}：{s}{'...' if n>3 else ''}")
            self._st(f"找到 {n} 個{star}",GRN)

    def _do_scan(self,key,vb):
        if not self._chk(): return
        rv=getattr(self,f"_r_{key}"); btn=getattr(self,f"_btn_{key}")
        def do(): return scan_value(self._pm,vb,self._stop,self._led_cb)
        def done(r):
            self._stats[key].candidates=r; self._set_res(key,r)
            btn.config(text="🔍 掃描",bg=ACC)
            # 候選 ≤5 且尚未學習指標 → 自動學習
            if 1<=len(r)<=5 and not self._stats[key].has_stable():
                self._bg_learn_stat(key,r[0])
        btn.config(text="⏹ 停止",bg=RED,command=lambda:self._stop.set())
        rv.set("掃描中..."); self._bg(do,done,rv,btn)

    def _bg_learn_stat(self,key,target_addr):
        """對一般數值做多層指標掃描，學習持久指標"""
        if not self._pm: return
        self._st(f"[{key}] 自動學習指標（多層）...",TEAL)
        def do(tgt=target_addr):
            return multilevel_ptr_scan(self._pm,tgt,max_depth=3,
                                       max_off=0x800,stop_evt=self._stop,
                                       progress_cb=self._led_cb)
        def done(results,k=key,tgt=target_addr):
            st=self._stats[k]
            valid=[r for r in results if resolve_ml_ptr(self._pm,r)==tgt]
            if valid:
                valid.sort(key=lambda r:r['depth'])
                st.ptr_chain=valid[0]; self._save_data()
                self._set_res(k,st.candidates)
                self._st(f"[{k}] 指標學習成功 {valid[0]['depth']} 層，鎖定後重啟自動恢復",GRN)
            else:
                self._st(f"[{k}] 指標學習失敗，縮小候選到1個再試",YEL)
        self._bg(do,done)

    def _scan_gold(self):
        try: v=int(self._v_gold.get().replace(',',''))
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('gold',struct.pack('<I',enc_gold(v)))
    def _write_gold(self):
        st=self._stats['gold']
        if not self._pm or(not st.candidates and not st.has_stable()):
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_gold.get().replace(',',''))
        except: return
        st.write_value(self._pm,v); self._st(f"金幣={v:,}",GRN)

    def _scan_weight(self):
        try: v=int(self._v_weight.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('weight',struct.pack('<i',v))
    def _write_weight(self):
        st=self._stats['weight']
        if not self._pm or(not st.candidates and not st.has_stable()):
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_weight.get())
        except: return
        st.write_value(self._pm,v); self._st(f"負重={v}",GRN)

    def _scan_spd(self):
        try: v=float(self._v_spd.get())
        except: messagebox.showerror("錯誤","請輸入浮點數"); return
        self._do_scan('spd',struct.pack('<f',v))
    def _write_spd(self):
        st=self._stats['spd']
        if not self._pm or(not st.candidates and not st.has_stable()):
            messagebox.showwarning("提示","請先掃描"); return
        try: v=float(self._v_spd.get())
        except: return
        st.write_value(self._pm,v); self._st(f"速度={v}",GRN)

    def _scan_mv(self):
        try: v=int(self._v_mv.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('mv',struct.pack('<i',v))
    def _write_mv(self):
        st=self._stats['mv']
        if not self._pm or(not st.candidates and not st.has_stable()):
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_mv.get())
        except: return
        st.write_value(self._pm,v); self._st(f"移動格={v}",GRN)

    def _scan_rng(self):
        try: v=int(self._v_rng.get())
        except: messagebox.showerror("錯誤","請輸入整數"); return
        self._do_scan('rng',struct.pack('<i',v))
    def _write_rng(self):
        st=self._stats['rng']
        if not self._pm or(not st.candidates and not st.has_stable()):
            messagebox.showwarning("提示","請先掃描"); return
        try: v=int(self._v_rng.get())
        except: return
        st.write_value(self._pm,v); self._st(f"攻距={v}",GRN)

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
