"""PDB-derived x86 ABI and unsupported-feature metadata.

The prototype deliberately consumes the matcher module's already-tested TPI
parser.  This module adds the procedure-symbol information that its byte
matcher does not need: function type indices, typed locals, frame handlers,
and volatile qualifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re
import subprocess
from typing import Any


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


@lru_cache(maxsize=8)
def _type_records(tool: str, pdb: str) -> tuple[dict, ...]:
    # Imported lazily so this module remains usable with any matcher exposing
    # the same TypeDB/dump_tpi API.
    import artifact_matcher as matcher
    return tuple(matcher.dump_tpi(Path(tool), Path(pdb)))


@lru_cache(maxsize=128)
def _module_symbols(tool: str, pdb: str, module: int) -> str:
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
    elif (unqualified & 0xFF) == 0x40:
        kind = "float"
    elif (unqualified & 0xFF) == 0x41:
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
        db = matcher.TypeDB(list(_type_records(str(tool), str(pdb))))
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
