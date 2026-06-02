"""單元測試：測試不依賴 pymem / 真實進程的純邏輯函式"""
import ctypes, struct, sys, unittest
from unittest.mock import MagicMock, patch

# ── Linux 沒有 ctypes.windll，先 mock 上去 ────────────────────────
if not hasattr(ctypes, 'windll'):
    ctypes.windll = MagicMock()
ctypes.windll.shell32.IsUserAnAdmin = lambda: 1

# ── Mock pymem / tkinter（Linux 環境沒裝）────────────────────────
for mod in ['pymem','pymem.pattern','pymem.process','pymem.memory',
            'pymem.ressources','pymem.ressources.structure',
            'tkinter','tkinter.messagebox']:
    sys.modules[mod] = MagicMock()

# ── import trainer 模組 ───────────────────────────────────────────
import importlib.util
spec = importlib.util.spec_from_file_location(
    "trainer", "/mnt/e/Wartales/save/wartales_trainer.py")
module = importlib.util.module_from_spec(spec)
sys.modules['trainer'] = module
try:
    spec.loader.exec_module(module)
except SystemExit:
    pass

resolve_ptr    = module.resolve_ptr
resolve_ml_ptr = module.resolve_ml_ptr
pointer_rescan = module.pointer_rescan
enc_gold       = module.enc_gold
CharEntry      = module.CharEntry


# ══════════════════════════════════════════════════════════════════
class TestEncGold(unittest.TestCase):

    def test_encrypted_differs_from_plain(self):
        for v in [0, 1, 100, 99999, 9999999]:
            enc = enc_gold(v)
            self.assertNotEqual(enc, v, f"enc_gold({v}) 沒有加密")
            self.assertLessEqual(enc, 0xFFFFFFFF)

    def test_deterministic(self):
        self.assertEqual(enc_gold(1000), enc_gold(1000))


# ══════════════════════════════════════════════════════════════════
class TestResolvePtr(unittest.TestCase):

    def test_basic(self):
        PTR_ADDR, PTR_VALUE, OFFSET = 0x1000, 0x5000, 0x40
        pm = MagicMock()
        module.read8 = lambda pm_, a: PTR_VALUE if a == PTR_ADDR else None
        self.assertEqual(resolve_ptr(pm, PTR_ADDR, OFFSET), PTR_VALUE + OFFSET)

    def test_bad_ptr_returns_none(self):
        pm = MagicMock()
        module.read8 = lambda pm_, a: None
        self.assertIsNone(resolve_ptr(pm, 0xDEAD, 0x40))


# ══════════════════════════════════════════════════════════════════
class TestResolveMLPtr(unittest.TestCase):

    def _setup_module_base(self, base):
        module.get_module_base = lambda pm_, n="Wartales.exe": base

    def test_1level(self):
        MOD_BASE, REL, PTR_VALUE, OFF = 0x140000000, 0x100, 0x20000000, 0x50
        self._setup_module_base(MOD_BASE)
        module.read8 = lambda pm_, a: PTR_VALUE if a == (MOD_BASE + REL) else None
        chain = {'rel_base': REL, 'offsets': [OFF], 'depth': 1}
        self.assertEqual(resolve_ml_ptr(MagicMock(), chain), PTR_VALUE + OFF)

    def test_2level(self):
        MOD_BASE = 0x140000000
        REL      = 0x200
        OBJ1     = 0x30000000
        OFF1     = 0x18           # static 解引後 +OFF1 得到下一層指標位置
        OBJ2     = 0x40000000
        OFF2     = 0x2C           # hp 在 obj2+OFF2
        memory = {MOD_BASE + REL: OBJ1, OBJ1 + OFF1: OBJ2}
        self._setup_module_base(MOD_BASE)
        module.read8 = lambda pm_, a: memory.get(a)
        chain = {'rel_base': REL, 'offsets': [OFF1, OFF2], 'depth': 2}
        self.assertEqual(resolve_ml_ptr(MagicMock(), chain), OBJ2 + OFF2)

    def test_broken_chain_returns_none(self):
        self._setup_module_base(0x140000000)
        module.read8 = lambda pm_, a: None
        chain = {'rel_base': 0x100, 'offsets': [0x10, 0x20], 'depth': 2}
        self.assertIsNone(resolve_ml_ptr(MagicMock(), chain))

    def test_no_module_base_returns_none(self):
        module.get_module_base = lambda pm_, n="Wartales.exe": None
        chain = {'rel_base': 0x100, 'offsets': [0x10], 'depth': 1}
        self.assertIsNone(resolve_ml_ptr(MagicMock(), chain))


# ══════════════════════════════════════════════════════════════════
class TestPointerRescan(unittest.TestCase):
    """確認 pointer_rescan 確實用 max_off 而非硬編碼值"""

    def test_keeps_exact_match(self):
        TARGET, OFF, PTR_ADDR = 0x50000, 0x40, 0x1000
        module.read8 = lambda pm_, a: (TARGET - OFF) if a == PTR_ADDR else None
        result = pointer_rescan(MagicMock(), [(PTR_ADDR, OFF)], TARGET, max_off=0x800)
        self.assertEqual(result, [(PTR_ADDR, OFF)])

    def test_rejects_beyond_max_off(self):
        TARGET, OFF, PTR_ADDR = 0x50000, 0x40, 0x1000
        # 故意讓偏差 = max_off + 1
        module.read8 = lambda pm_, a: (TARGET - OFF - 0x801) if a == PTR_ADDR else None
        result = pointer_rescan(MagicMock(), [(PTR_ADDR, OFF)], TARGET, max_off=0x800)
        self.assertEqual(result, [])

    def test_boundary_max_off(self):
        """剛好等於 max_off 的偏差應保留"""
        TARGET, OFF, PTR_ADDR, MAX = 0x50000, 0x40, 0x1000, 0x100
        module.read8 = lambda pm_, a: (TARGET - OFF - MAX) if a == PTR_ADDR else None
        result = pointer_rescan(MagicMock(), [(PTR_ADDR, OFF)], TARGET, max_off=MAX)
        self.assertEqual(result, [(PTR_ADDR, OFF)])

    def test_small_max_off_rejects_large_delta(self):
        """用小 max_off（如舊版硬編碼 16）應過濾掉較大偏差"""
        TARGET, OFF, PTR_ADDR = 0x50000, 0x40, 0x1000
        module.read8 = lambda pm_, a: (TARGET - OFF - 100) if a == PTR_ADDR else None
        # max_off=16 應拒絕，max_off=200 應接受
        self.assertEqual(pointer_rescan(MagicMock(), [(PTR_ADDR, OFF)], TARGET, max_off=16), [])
        self.assertEqual(pointer_rescan(MagicMock(), [(PTR_ADDR, OFF)], TARGET, max_off=200),
                         [(PTR_ADDR, OFF)])


# ══════════════════════════════════════════════════════════════════
class TestCharEntry(unittest.TestCase):

    def test_roundtrip_ptr_chain(self):
        e = CharEntry("戰士", "主坦")
        e.ptr_chain = {'rel_base': 0x100, 'offsets': [0x10, 0x20], 'depth': 2}
        e.locked, e.lock_val = True, 9999
        e2 = CharEntry.from_dict(e.to_dict())
        self.assertEqual(e2.name, "戰士")
        self.assertEqual(e2.ptr_chain, e.ptr_chain)
        self.assertTrue(e2.locked)
        self.assertEqual(e2.lock_val, 9999)

    def test_has_stable(self):
        e = CharEntry("A")
        self.assertFalse(e.has_stable())
        e.ptr_chain = {'rel_base': 0, 'offsets': [0], 'depth': 1}
        self.assertTrue(e.has_stable())

    def test_stable_label(self):
        e = CharEntry("B")
        self.assertEqual(e.stable_label(), "○")
        e.stable_ptr = {'ptr_addr': 0, 'offset': 0, 'rel_base': 0, 'is_static': True}
        self.assertEqual(e.stable_label(), "★")
        e.ptr_chain = {'rel_base': 0, 'offsets': [0, 0], 'depth': 2}
        self.assertEqual(e.stable_label(), "★2")

    def test_from_dict_old_format_defaults(self):
        """舊版 JSON（無 locked/lock_val/ptr_chain）應有安全預設值"""
        e = CharEntry.from_dict({'name': 'X', 'note': '', 'stable_ptr': None})
        self.assertFalse(e.locked)
        self.assertIsNone(e.lock_val)
        self.assertIsNone(e.ptr_chain)

    def test_write_hp_no_addr_returns_false(self):
        e = CharEntry("C")
        # 沒有任何指標，write_hp 應回傳 False 而不是崩潰
        self.assertFalse(e.write_hp(MagicMock(), 9999))


if __name__ == '__main__':
    unittest.main(verbosity=2)
