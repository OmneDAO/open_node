# vm/compiler.py
"""
Compile user supplied source to a *canonical* byte-code sequence.

We rely on CPython's `compile()` → byte-code and then *strip* all
non-deterministic fields (filenames, line-numbers, flags, etc.).
"""
from types import CodeType
import dis, marshal, hashlib, ast, textwrap, RestrictedPython

CANON_HEADER = b"OMNE:VM:PY:1\n"

def canonical_compile(src: str) -> tuple[bytes, str, int]:
    """
    Returns (bytecode_bytes, code_hash_hex, static_gas)
    """
    # ── 1. basic restrictions with RestrictedPython ──────────────
    _globals = RestrictedPython.Guards.full_write_guarded_map()
    bytecode = compile(textwrap.dedent(src), filename="<omne>", mode="exec")
    code_obj: CodeType = bytecode

    # ── 2. canonicalise: strip co_filename, firstlineno, flags … ─
    def strip(c: CodeType) -> CodeType:
        return CodeType(
            c.co_argcount, c.co_kwonlyargcount, c.co_nlocals,
            c.co_stacksize, c.co_flags,
            c.co_code, c.co_consts, c.co_names, c.co_varnames,
            "<omne>",  # co_filename
            c.co_name,
            0,         # firstlineno
            b"",       # lnotab
            (), (), () # freevars, cellvars
        )
    canon_obj = strip(code_obj)
    canon_bytes = CANON_HEADER + marshal.dumps(canon_obj)

    # ── 3. static gas estimation by disassembly ──────────────────
    static_gas = 0
    OPCOST = load_opcode_cost_table()
    for op in dis.Bytecode(canon_obj):
        static_gas += OPCOST.get(op.opname, 0)

    return canon_bytes, hashlib.sha256(canon_bytes).hexdigest(), static_gas

def load_opcode_cost_table() -> dict[str, int]:
    # reserved object path in registry → pulled once at startup
    try:
        from object_registry import global_registry
        raw = global_registry.get("__vm/opcode_costs/current")
        return json.loads(raw) if raw else {}
    except Exception:
        return {}
