"""PDB-derived x86 ABI and unsupported-feature metadata.

The prototype deliberately consumes the matcher module's already-tested TPI
parser.  This module adds the procedure-symbol information that its byte
matcher does not need: function type indices, typed locals, frame handlers,
and volatile qualifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import pickle
import re
import subprocess
from typing import Any

from artifact_cache import file_identity


PROCEDURE_LINE = re.compile(r"^\s*(\d+)\s+\|\s+S_[GL]PROC32(?:_ID)?\b")
PROCEDURE_END = re.compile(r"\bend\s*=\s*(\d+)")
TYPE_INDEX = re.compile(r"\btype\s*=\s*`?0x([0-9A-Fa-f]+)")
TYPED_SYMBOL = re.compile(
    r"^\s*\d+\s+\|\s+S_(?:BPREL32|REGREL32|LOCAL|REGISTER|GDATA32|LDATA32)\b"
)
HANDLER_ADDRESS = re.compile(r"exception handler addr\s*=\s*(\d+):(\d+)")
EXCEPTION_SYMBOL_PARTS = (
    "_CxxThrowException", "__CxxFrameHandler", "__CxxLongjmpUnwind",
    "_except_handler", "_EH_prolog", "_EH_epilog", "__DestructExceptionObject",
)


@dataclass(frozen=True)
class ABIType:
    type_index: int
    name: str
    size: int
    kind: str
    volatile: bool = False
    restrict: bool = False
    pointee_size: int | None = None
    pointee_type: int | None = None

    @property
    def pointer(self) -> bool:
        return self.kind == "pointer"


@dataclass(frozen=True)
class ABISignature:
    type_index: int
    calling_convention: str
    return_type: ABIType
    parameters: tuple[ABIType, ...]
    variadic: bool = False
    implicit_this: bool = False


@dataclass(frozen=True)
class FunctionMetadata:
    signature: ABISignature | None
    issues: tuple[str, ...]
    typed_symbol_indices: tuple[int, ...] = ()


CACHE_DIRECTORY = Path(
    os.environ.get("REVIVE_CACHE") or Path(__file__).resolve().parent.parent / ".cache"
)


def _type_database(tool: str, pdb: str):
    import artifact_matcher as matcher
    return _cached_type_database(tool, pdb, file_identity(tool), file_identity(pdb),
                                 file_identity(matcher.__file__))


@lru_cache(maxsize=8)
def _cached_type_database(tool: str, pdb: str, tool_id: tuple, pdb_id: tuple, matcher_id: tuple):
    """The matcher's TypeDB for a PDB, parsed once and cached on disk.

    Parsing a PDB's type stream from llvm-pdbutil output takes 10-20 s and
    every worker needs both PDBs. The pickle is keyed by the identities of
    the PDB, parser and tool (paths and file revisions), so rebuilt/replaced
    inputs cannot reuse an older database in a persistent worker.
    """
    # Imported lazily so this module remains usable with any matcher exposing
    # the same TypeDB/dump_tpi API.
    import artifact_matcher as matcher

    key = hashlib.sha256(repr((tool_id, pdb_id, matcher_id)).encode()).hexdigest()
    cache = CACHE_DIRECTORY / f"types-{key}.pickle"
    try:
        with cache.open("rb") as stream:
            return pickle.load(stream)
    except (OSError, pickle.PickleError, EOFError, AttributeError, ImportError):
        pass
    database = matcher.TypeDB(list(matcher.dump_tpi(Path(tool), Path(pdb))))
    try:
        CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)
        temporary = cache.with_name(f"{cache.name}.{os.getpid()}.tmp")
        with temporary.open("wb") as stream:
            pickle.dump(database, stream, protocol=pickle.HIGHEST_PROTOCOL)
        temporary.replace(cache)
    except OSError:
        pass
    return database


def type_database(matcher: Any, tool: Path, pdb: Path):
    return _type_database(str(tool), str(pdb))


def normalized_path(value: str | Path) -> str:
    """Comparable path spelling without touching the filesystem."""
    return os.path.normcase(os.path.abspath(str(value)))


def _module_symbols(tool: str, pdb: str, module: int) -> str:
    return _cached_module_symbols(tool, pdb, module, file_identity(tool), file_identity(pdb))


@lru_cache(maxsize=128)
def _cached_module_symbols(tool: str, pdb: str, module: int, tool_id: tuple, pdb_id: tuple) -> str:
    result = subprocess.run(
        [tool, "dump", "--symbols", f"--modi={module}", pdb],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode:
        raise RuntimeError(f"llvm-pdbutil failed reading module {module}: {result.stderr.strip()}")
    return result.stdout


def _procedure_block(text: str, record_offset: int) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if (match := PROCEDURE_LINE.match(line)) and
                  int(match.group(1)) == record_offset), None)
    if start is None:
        raise RuntimeError(f"PDB procedure record {record_offset} was not found")
    end_match = PROCEDURE_END.search(lines[start + 1]) if start + 1 < len(lines) else None
    if end_match is None:
        raise RuntimeError(f"PDB procedure record {record_offset} has no end offset")
    end_offset = int(end_match.group(1))
    end = next((i + 1 for i in range(start + 1, len(lines))
                if re.match(rf"^\s*{end_offset}\s+\|\s+S_END\b", lines[i])), None)
    if end is None:
        raise RuntimeError(f"PDB procedure record {record_offset} has no S_END")
    return "\n".join(lines[start:end])


def _qualifiers(db: Any, index: int) -> tuple[bool, bool, int]:
    volatile = False
    restrict = False
    current = index
    while current >= 0x1000:
        record = db.get(current)
        if not record:
            break
        kind = record.get("Kind")
        if kind == "LF_MODIFIER":
            body = record.get("Modifier") or {}
            modifiers = body.get("Modifiers") or []
            volatile |= "Volatile" in modifiers
            current = body.get("ModifiedType", current)
            continue
        if kind == "LF_POINTER":
            attrs = int((record.get("Pointer") or {}).get("Attrs") or 0)
            volatile |= bool(attrs & (1 << 9))
            restrict |= bool(attrs & (1 << 12))
        break
    return volatile, restrict, current


def _abi_type(matcher: Any, db: Any, index: int) -> ABIType:
    volatile, restrict, unqualified = _qualifiers(db, index)
    simple_pointer = matcher.simple_pointer_base(unqualified)
    record = db.get(unqualified) if unqualified >= 0x1000 else None
    pointer = simple_pointer is not None or bool(record and record.get("Kind") == "LF_POINTER")
    pointee = None
    if simple_pointer is not None:
        pointee = simple_pointer
    elif pointer:
        pointee = (record.get("Pointer") or {}).get("ReferentType")
    size = matcher.type_size(db, unqualified)
    if size is None:
        raise ValueError(f"PDB type 0x{index:x} has no ABI size")
    if pointer:
        kind = "pointer"
    # Simple (non-record) CodeView types only: T_REAL32 and T_REAL64. A
    # complex type index can share the low byte.
    elif unqualified == 0x40:
        kind = "float"
    elif unqualified == 0x41:
        kind = "double"
    elif size == 0:
        kind = "void"
    elif record and record.get("Kind") in matcher.CLASS_LIKE_KINDS | {"LF_UNION", "LF_ARRAY"}:
        kind = "aggregate"
    else:
        kind = "integer"
    return ABIType(
        index, matcher.describe_type(db, index), size, kind, volatile, restrict,
        matcher.type_size(db, pointee) if pointee is not None else None,
        pointee,
    )


def _contains_volatile(db: Any, index: int | None, seen: frozenset[int] = frozenset()) -> bool:
    if index is None or index < 0x1000 or index in seen:
        return False
    record = db.get(index)
    if not record:
        return False
    visited = seen | {index}
    kind = record.get("Kind")
    if kind == "LF_MODIFIER":
        body = record.get("Modifier") or {}
        return (
            "Volatile" in (body.get("Modifiers") or []) or
            _contains_volatile(db, body.get("ModifiedType"), visited)
        )
    if kind == "LF_POINTER":
        body = record.get("Pointer") or {}
        return (
            bool(int(body.get("Attrs") or 0) & (1 << 9)) or
            _contains_volatile(db, body.get("ReferentType"), visited)
        )
    if kind == "LF_ARRAY":
        return _contains_volatile(
            db, (record.get("Array") or {}).get("ElementType"), visited,
        )
    if kind in ("LF_STRUCTURE", "LF_CLASS", "LF_UNION"):
        key = "Union" if kind == "LF_UNION" else "Class"
        field_list = (record.get(key) or {}).get("FieldList")
        field_record = db.get(field_list)
        if field_record:
            for item in field_record.get("FieldList") or []:
                body = item.get("DataMember") or item.get("BaseClass") or {}
                if _contains_volatile(db, body.get("Type"), visited):
                    return True
    return False


def _signature(matcher: Any, db: Any, index: int) -> ABISignature:
    record = db.get(index)
    if not record or record.get("Kind") not in ("LF_PROCEDURE", "LF_MFUNCTION"):
        raise ValueError(f"PDB type 0x{index:x} is not a function type")
    implicit_this = record["Kind"] == "LF_MFUNCTION"
    body = record["MemberFunction" if implicit_this else "Procedure"]
    arguments = matcher.arg_types(db, body.get("ArgumentList"))
    if arguments is None:
        raise ValueError(f"PDB function type 0x{index:x} has no argument list")
    parameter_count = int(body.get("ParameterCount") or 0)
    variadic = bool(arguments and arguments[-1] == 0)
    if variadic:
        arguments = arguments[:-1]
    expected_count = parameter_count - (1 if variadic else 0)
    if len(arguments) != expected_count:
        raise ValueError(
            f"PDB function type 0x{index:x} declares {parameter_count} parameters "
            f"but lists {len(arguments)}"
        )
    parameters = tuple(_abi_type(matcher, db, item) for item in arguments)
    if implicit_this:
        parameters = (_abi_type(matcher, db, body["ThisType"]), *parameters)
    return ABISignature(
        index, str(body.get("CallConv") or ""),
        _abi_type(matcher, db, body["ReturnType"]), parameters,
        variadic, implicit_this,
    )


@dataclass(frozen=True)
class ParameterHome:
    """Where a parameter's value is at function entry.

    ``stack_offset`` is relative to the entry ESP (the return address is at
    offset 0). More than one location means the PDB admits several entry
    ABIs; a caller must then provide, and a callee may read, each of them.
    """

    registers: tuple[str, ...] = ()
    stack_offset: int | None = None

    @property
    def locations(self) -> int:
        return len(self.registers) + (self.stack_offset is not None)


def standard_parameter_homes(signature: ABISignature) -> tuple[ParameterHome, ...]:
    """Entry homes implied by the declared 32-bit MSVC calling convention."""
    convention = signature.calling_convention.lower()
    fastcall = convention in ("nearfast", "nearfastcall", "fastcall")
    thiscall = convention in ("thiscall", "nearthiscall")
    registers = ["ecx", "edx"] if fastcall else []
    homes: list[ParameterHome] = []
    offset = 4
    for index, parameter in enumerate(signature.parameters):
        if thiscall and index == 0:
            homes.append(ParameterHome(("ecx",)))
        elif registers and parameter.size <= 4 and parameter.kind in ("integer", "pointer"):
            homes.append(ParameterHome((registers.pop(0),)))
        else:
            homes.append(ParameterHome((), offset))
            offset += (parameter.size + 3) & ~3
    return tuple(homes)


PARAMETER_RECORD = re.compile(r"^\s*\d+\s+\|\s+S_(REGISTER|BPREL32)\b")
REGISTER_BODY = re.compile(r"register\s*=\s*(\w+),\s*type\s*=\s*`?0x([0-9A-Fa-f]+)")
HOME_REGISTERS = {"eax", "ecx", "edx", "ebx", "esi", "edi"}


def recorded_parameter_homes(
    matcher: Any, tool: Path, pdb: Path, record: dict[str, Any],
    signature: ABISignature, frame_prologue: bool,
) -> tuple[tuple[ParameterHome, ...] | None, tuple[str, ...]]:
    """Recover entry homes from a procedure's CodeView parameter records.

    MSVC gives TU-local functions custom register conventions that their
    procedure type does not describe; the parameter records do. They are
    matched to the signature by type in order. The declared convention is
    kept when the records agree with it, a custom layout is used when only
    it fits, and a register parameter that fits both is given both homes.
    Returns ``(None, ())`` for the declared convention.
    """
    standard = standard_parameter_homes(signature)
    text = _module_symbols(str(tool), str(pdb), int(record["module"]))
    lines = _procedure_block(text, int(record["record_offset"])).splitlines()
    has_frame_pointer = bool(
        (flags := PROCEDURE_FLAGS.search(" ".join(lines[:3]))) and "has fp" in flags.group(1)
    )
    records: list[tuple[str, int, str | int]] = []
    for position, line in enumerate(lines[:-1]):
        match = PARAMETER_RECORD.match(line)
        if not match:
            continue
        body = lines[position + 1]
        if match.group(1) == "REGISTER":
            parsed = REGISTER_BODY.search(body)
            if parsed:
                records.append(("register", int(parsed.group(2), 16), parsed.group(1).lower()))
        else:
            parsed = BPREL_BODY.search(body)
            if parsed:
                records.append(("stack", int(parsed.group(1), 16), int(parsed.group(2))))
    # Parameters are emitted first, in declaration order; unused ones may
    # have no record. Match by exact type index.
    recorded: list[tuple[str, str | int] | None] = []
    cursor = 0
    for parameter in signature.parameters:
        if cursor < len(records) and records[cursor][1] == parameter.type_index:
            recorded.append((records[cursor][0], records[cursor][2]))
            cursor += 1
        else:
            recorded.append(None)
    # Without a register record there is no sign of a custom convention.
    if not any(item and item[0] == "register" for item in recorded):
        return None, ()
    if any(item and item[0] == "register" and item[1] not in HOME_REGISTERS for item in recorded):
        return None, ("UNSUPPORTED_PDB_ABI:unexpected parameter register",)
    if not (has_frame_pointer and frame_prologue):
        # Stack records of a frame without the standard EBP prologue have no
        # usable base. A register parameter after every stack parameter
        # leaves both conventions with the same stack layout, so it is given
        # both homes; anything else cannot be placed.
        registers = [item[1] for item in recorded if item and item[0] == "register"]
        on_stack = [
            home.stack_offset is not None and not (item and item[0] == "register")
            for home, item in zip(standard, recorded, strict=True)
        ]
        trailing = all(
            not any(on_stack[index + 1:])
            for index, (home, item) in enumerate(zip(standard, recorded, strict=True))
            if item and item[0] == "register" and home.stack_offset is not None
        )
        if None in recorded or len(set(registers)) != len(registers) or not trailing:
            return None, ("UNSUPPORTED_PDB_ABI:register parameters without an EBP frame",)
        return tuple(
            ParameterHome(tuple(dict.fromkeys((*home.registers, item[1]))), home.stack_offset)
            if item[0] == "register" else home
            for home, item in zip(standard, recorded, strict=True)
        ), ()

    # Declared convention: recorded stack homes must be the standard ones; a
    # recorded register may merely be where the body keeps the value.
    standard_fits = all(
        item is None or item[0] == "register" or home.stack_offset == item[1] - 4
        for home, item in zip(standard, recorded, strict=True)
    )
    # Custom convention: every parameter recorded, stack parameters packed
    # from offset 4 in order, registers distinct.
    custom_fits = None not in recorded
    if custom_fits:
        offset = 4
        registers: set[str] = set()
        for parameter, item in zip(signature.parameters, recorded, strict=True):
            if item[0] == "stack":
                custom_fits &= item[1] - 4 == offset
                offset += (parameter.size + 3) & ~3
            else:
                custom_fits &= item[1] not in registers
                registers.add(item[1])
    if custom_fits and not standard_fits:
        return tuple(
            ParameterHome((item[1],)) if item[0] == "register" else ParameterHome((), item[1] - 4)
            for item in recorded
        ), ()
    if standard_fits and custom_fits:
        return tuple(
            ParameterHome(tuple(dict.fromkeys((*home.registers, item[1]))), home.stack_offset)
            if item[0] == "register" else home
            for home, item in zip(standard, recorded, strict=True)
        ), ()
    if standard_fits:
        return None, ()
    return None, ("UNSUPPORTED_PDB_ABI:parameter records fit no entry convention",)


BPREL_LOCAL = re.compile(r"^\s*\d+\s+\|\s+S_BPREL32\b.*`([^`]*)`\s*$")
BPREL_BODY = re.compile(r"type\s*=\s*`?0x([0-9A-Fa-f]+).*\boffset\s*=\s*(-?\d+)")
PROCEDURE_FLAGS = re.compile(r"\bflags\s*=\s*(.*)$")


@dataclass(frozen=True)
class FrameLocal:
    name: str
    frame_offset: int  # relative to EBP after `push ebp; mov ebp, esp`
    size: int


@dataclass(frozen=True)
class FrameLayout:
    """EBP-relative stack objects declared by a procedure's CodeView record.

    ``complete`` is false when the record describes storage this parser does
    not map (register-relative locals, a missing frame pointer, or an
    unsized type); such objects are then left to conservative escape extents.
    """

    has_frame_pointer: bool
    locals: tuple[FrameLocal, ...]
    complete: bool


def frame_layout(matcher: Any, tool: Path, pdb: Path, record: dict[str, Any]) -> FrameLayout:
    text = _module_symbols(str(tool), str(pdb), int(record["module"]))
    lines = _procedure_block(text, int(record["record_offset"])).splitlines()
    header = " ".join(lines[:3])
    flags = PROCEDURE_FLAGS.search(header)
    has_frame_pointer = bool(flags and "has fp" in flags.group(1))
    db = type_database(matcher, tool, pdb)
    found: list[FrameLocal] = []
    complete = has_frame_pointer
    for position, line in enumerate(lines):
        if re.search(r"\bS_(REGREL32|LOCAL|DEFRANGE\w*)\b", line):
            complete = False
        match = BPREL_LOCAL.match(line)
        if not match or position + 1 >= len(lines):
            continue
        body = BPREL_BODY.search(lines[position + 1])
        if body is None:
            complete = False
            continue
        size = matcher.type_size(db, int(body.group(1), 16))
        if not size:
            complete = False
            continue
        found.append(FrameLocal(match.group(1), int(body.group(2)), size))
    return FrameLayout(has_frame_pointer, tuple(found), complete)


def extract_function_metadata(
    matcher: Any, tool: Path, pdb: Path, record: dict[str, Any],
    relocation_symbols: tuple[str, ...] = (),
    *, build: Path | None = None, inventory: dict[str, Any] | None = None,
) -> FunctionMetadata:
    issues: list[str] = []
    try:
        text = _module_symbols(str(tool), str(pdb), int(record["module"]))
        block = _procedure_block(text, int(record["record_offset"]))
        first_type = TYPE_INDEX.search(block)
        if first_type is None:
            raise RuntimeError("procedure has no CodeView function type")
        function_index = int(first_type.group(1), 16)
        db = type_database(matcher, tool, pdb)
        signature = _signature(matcher, db, function_index)
        block_lines = block.splitlines()
        typed: list[int] = []
        for position, line in enumerate(block_lines):
            if not TYPED_SYMBOL.match(line):
                continue
            joined = " ".join(block_lines[position:position + 3])
            match = TYPE_INDEX.search(joined)
            if match:
                typed.append(int(match.group(1), 16))
        typed_indices = tuple(typed)
        function_record = db.get(function_index)
        function_body = function_record[
            "MemberFunction" if function_record.get("Kind") == "LF_MFUNCTION" else "Procedure"
        ]
        function_types = [function_body.get("ReturnType")]
        function_types.extend(matcher.arg_types(db, function_body.get("ArgumentList")) or [])
        # Volatile affects compiler access ordering, which is already embodied
        # by each instruction stream.  In this single-threaded relational
        # model the actual ordered reads/writes are the observable behavior.
        if build is not None and inventory is not None:
            globals_by_name = matcher.load_globals(build, pdb, tool, False)
            data_types: dict[str, set[int]] = {}
            for item in inventory.get("data_symbols", []):
                data_types.setdefault(item["name"], set()).add(item["type"])
            for name, values in globals_by_name.items():
                data_types.setdefault(name, set()).update(item["type"] for item in values)
            for symbol in relocation_symbols:
                candidates = {symbol, symbol.lstrip("_@")}
                indices = {index for name in candidates for index in data_types.get(name, ())}
                # As above, volatile data accesses remain ordinary ordered
                # memory events for this single-threaded proof.
                _ = indices
    except (KeyError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        signature = None
        typed_indices = ()
        issues.append(f"UNSUPPORTED_PDB_ABI:{error}")
    return FunctionMetadata(signature, tuple(dict.fromkeys(issues)), typed_indices)
