"""Extract a reference/candidate function pair using an existing matcher API.

This is temporary prototype glue. It lets the symbolic engine consume live PE,
PDB, and COFF data before Revive has its own artifact frontend.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, replace
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import sys

import capstone

from pdb_frontend import (
    ABISignature, ABIType, extract_function_metadata, normalized_path,
    recorded_parameter_homes, type_database,
)


class RelocationResolutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class MemoryObjectContract:
    logical_id: str
    address: int
    size: int
    content: bytes | None = None
    type_index: int | None = None  # target PDB type, when one names the object


@dataclass(frozen=True)
class PointerGlobalContract:
    logical_id: str
    address: int
    pointee_size: int


TLS_ARRAY_POINTER = 0x2C
# Outside the synthetic constant range (_synthetic_rva) and alias allocations.
TLS_ARRAY_BASE = 0x30000000
TLS_BLOCK_BASE = 0x31000000


def _word_type(name: str = "unsigned int", *, pointer: bool = False) -> ABIType:
    return ABIType(0, name, 4, "pointer" if pointer else "integer",
                   pointee_size=1 if pointer else None)


def _runtime_call_target(address: int, symbol: str):
    """Return ABI metadata for compiler/runtime publics lacking PDB owners."""
    from angr_equiv import CallTarget

    if symbol in ("__CIsqrt", "__ftol2_sse"):
        return _untyped_call_target(address, symbol, [])

    specifications = {
        "@__security_check_cookie@4": (
            "NearFast", ABIType(0, "void", 0, "void"), (_word_type(),),
        ),
        "___security_check_cookie@4": (
            "NearFast", ABIType(0, "void", 0, "void"), (_word_type(),),
        ),
        "_memset": (
            "NearC", _word_type("void *", pointer=True),
            (_word_type("void *", pointer=True), _word_type(), _word_type()),
        ),
        "_AIL_last_error@0": (
            "NearStdCall", _word_type("char *", pointer=True), (),
        ),
    }
    specification = specifications.get(symbol)
    if specification is None:
        return None
    convention, return_type, parameters = specification
    signature = ABISignature(0, convention, return_type, parameters)
    return CallTarget(
        address, symbol, len(parameters),
        return_register="eax", signature=signature,
    )


C_STDCALL_SYMBOL = re.compile(r"^_[A-Za-z_$][\w$]*@(\d+)$")
C_CDECL_SYMBOL = re.compile(r"^_[A-Za-z_$][\w$]*$")


def _untyped_call_target(address: int, symbol: str,
                         callsites: list[tuple[int, int | None]]):
    """Derive a word ABI for a PDB-absent callee only when it is certain.

    C decoration fixes stdcall stack size. An undecorated C symbol is cdecl,
    whose argument count is known only when every call site pops it. Other
    identities (C++ mangling, fastcall, unnamed addresses) are rejected
    rather than guessed, because a wrong ABI silently drops arguments.
    """
    from angr_equiv import CallTarget

    if symbol == "__CIsqrt":
        signature = ABISignature(
            0, "NearC", ABIType(0, "double", 8, "double"), (),
        )
        # Consumes ST0 and returns the root in ST0.
        return CallTarget(
            address, symbol, 0, argument_registers=("x87_st0",),
            return_register="x87_st0", signature=signature, x87_pops=1,
        )
    if symbol == "__ftol2_sse":
        signature = ABISignature(
            0, "NearC", ABIType(0, "__int64", 8, "integer"), (),
        )
        # Converts and pops ST0, like FISTP, returning EDX:EAX.
        return CallTarget(
            address, symbol, 0, argument_registers=("x87_st0",),
            return_register="edx_eax", signature=signature, x87_pops=1,
        )

    stdcall = C_STDCALL_SYMBOL.match(symbol)
    if stdcall:
        convention, count = "NearStdCall", int(stdcall.group(1)) // 4
    elif C_CDECL_SYMBOL.match(symbol):
        counts = {count for _, count in callsites}
        if not callsites or None in counts or len(counts) != 1:
            return CallTarget(address, symbol, 0, frontend_issues=(
                f"UNSUPPORTED_CALL_ABI:{symbol}:cdecl argument count is not fixed by every call site",
            ))
        convention, count = "NearC", counts.pop()
    else:
        return CallTarget(address, symbol, 0, frontend_issues=(
            f"UNSUPPORTED_CALL_ABI:{symbol}:no PDB procedure type",
        ))
    parameters = tuple(_word_type() for _ in range(count))
    signature = ABISignature(0, convention, _word_type(), parameters)
    return CallTarget(address, symbol, count, signature=signature)


def _synthetic_rva(pe, identity: bytes) -> int:
    digest = hashlib.sha256(identity).digest()
    address = 0x20000000 + (int.from_bytes(digest[:3], "little") << 6)
    return address - pe.image_base


def execution_metadata(pair: dict) -> dict:
    """Arguments that make execute() honor the authoritative PDB contract."""
    return {"signature": pair["signature"], "frontend_issues": pair["frontend_issues"]}


def _procedure_metadata_record(inventory: dict, record: dict) -> dict:
    if "record_offset" in record:
        return record
    owners = [item for item in inventory.get("procedures", [])
              if item.get("module") == record.get("module") and
              item.get("section") == record.get("section") and
              item.get("offset") == record.get("offset") and
              item.get("name") == record.get("procedure")]
    return owners[0] if len(owners) == 1 else record


def pdb_call_target(
    pair: dict, address: int, decorated_symbol: str, *,
    fresh_result: bool = True, havoc_memory: bool = True,
):
    """Build an external-call summary directly from its PDB procedure type."""
    from angr_equiv import CallTarget

    runtime = _runtime_call_target(address, decorated_symbol)
    if runtime is not None:
        return runtime, None

    matcher = pair["matcher"]
    try:
        record = matcher.resolve_selector(decorated_symbol, pair["inventory"], pair["pe"])
    except Exception:
        target_rva = address - pair["pe"].image_base
        matches = [
            item for item in pair["inventory"].get("procedures", ())
            if pair["pe"].rva(item["section"], item["offset"]) == target_rva
        ]
        if len(matches) != 1:
            return CallTarget(
                address, decorated_symbol, 0,
                frontend_issues=(f"UNSUPPORTED_CALL_IDENTITY:{decorated_symbol}",),
            ), None
        record = matches[0]
    record = _procedure_metadata_record(pair["inventory"], record)
    relocation_symbols: tuple[str, ...] = ()
    try:
        object_path = matcher.candidate_path(pair["build"], record)
        coff = matcher.coff_function(object_path, decorated_symbol)
        relocation_symbols = tuple(
            item.get("target") or "" for item in coff.get("relocations", ())
        )
    except Exception:
        # The target PDB remains authoritative for the ABI even when the
        # reconstruction does not emit a body for this external procedure.
        relocation_symbols = ()
    metadata = extract_function_metadata(
        matcher, pair["tool"], pair["pdb"], record,
        relocation_symbols,
        build=pair["build"], inventory=pair["inventory"],
    )
    signature = metadata.signature
    return_register = (
        "x87_st0" if signature and signature.return_type.kind in ("float", "double")
        else "eax"
    )
    contract = CallTarget(
        address, decorated_symbol,
        len(signature.parameters) if signature else 0,
        fresh_result=fresh_result, havoc_memory=havoc_memory,
        return_register=return_register, signature=signature,
        frontend_issues=metadata.issues,
    )
    return contract, record


def _candidate_signature(pair: dict, candidate_record: dict, signature: ABISignature):
    """The candidate PDB's own view of a procedure's parameters.

    Parameter records carry candidate-PDB type indices, so entry homes must
    be recovered against the candidate's signature. It has to agree with the
    target's parameter layout; otherwise the ABIs differ outright.
    """
    metadata = extract_function_metadata(
        pair["matcher"], pair["tool"], candidate_pdb_path(pair["build"]), candidate_record,
    )
    candidate = metadata.signature
    if candidate is None:
        return None, metadata.issues or ("UNSUPPORTED_PDB_ABI:candidate signature",)
    shape = lambda value: tuple((item.size, item.kind) for item in value.parameters)
    if (shape(candidate) != shape(signature) or
            candidate.return_type.size != signature.return_type.size or
            candidate.calling_convention != signature.calling_convention):
        return None, (f"CANDIDATE_SIGNATURE_MISMATCH:{candidate.calling_convention}:"
                      f"{[item.name for item in candidate.parameters]}",)
    return candidate, ()


def entry_homes(pair: dict, reference_record: dict, signature: ABISignature,
                reference_prologue: bool, candidate_record: dict | None,
                candidate_prologue: bool):
    """Per-side entry homes: (reference, candidate, issues)."""
    matcher, tool = pair["matcher"], pair["tool"]
    reference_homes, issues = recorded_parameter_homes(
        matcher, tool, pair["pdb"], reference_record, signature, reference_prologue,
    )
    if candidate_record is None:
        # Custom conventions exist only for procedures the candidate PDB
        # describes; an absent body is reached through its declaration.
        return reference_homes, None, issues
    candidate_signature, candidate_issues = _candidate_signature(pair, candidate_record, signature)
    if candidate_signature is None:
        return reference_homes, None, (*issues, *candidate_issues)
    candidate_homes, candidate_issues = recorded_parameter_homes(
        matcher, tool, candidate_pdb_path(pair["build"]), candidate_record,
        candidate_signature, candidate_prologue,
    )
    return reference_homes, candidate_homes, (*issues, *candidate_issues)


def _candidate_record_for(pair: dict, target_record: dict, symbol: str) -> dict | None:
    candidate_pdb = candidate_pdb_path(pair["build"])
    if not candidate_pdb.is_file():
        return None
    matcher = pair["matcher"]
    index = _candidate_procedure_index(pair)
    publics = index["by_public"].get(symbol, ())
    if publics:
        return publics[0] if len(publics) == 1 else None
    try:
        wanted = normalized_path(matcher.candidate_path(pair["build"], target_record))
    except Exception:
        return None
    matches = [
        item for item in index["by_object"].get(wanted, ())
        if item.get("name") == target_record.get("name")
    ]
    return matches[0] if len(matches) == 1 else None


def _direct_calls(code: bytes, base: int) -> list[tuple[int, int, int | None]]:
    """Return (callsite, target, caller-cleaned stack argument count)."""
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    instructions = list(engine.disasm(code, base))
    result: list[tuple[int, int, int | None]] = []
    for index, instruction in enumerate(instructions):
        if (instruction.mnemonic != "call" or len(instruction.operands) != 1 or
                instruction.operands[0].type != capstone.x86_const.X86_OP_IMM):
            continue
        cleaned = None
        if index + 1 < len(instructions):
            following = instructions[index + 1]
            if (following.mnemonic == "add" and len(following.operands) == 2 and
                    following.operands[0].type == capstone.x86_const.X86_OP_REG and
                    following.reg_name(following.operands[0].reg) == "esp" and
                    following.operands[1].type == capstone.x86_const.X86_OP_IMM and
                    following.operands[1].imm >= 0 and following.operands[1].imm % 4 == 0):
                cleaned = following.operands[1].imm // 4
        result.append((instruction.address, instruction.operands[0].imm, cleaned))
    return result


def external_call_contracts(pair: dict):
    """PDB-typed summaries for every direct call leaving the function.

    Returns (reference contracts, candidate contracts): each side calls a
    TU-local callee through that side's own compiler-chosen entry homes.
    """
    base = pair["address"]
    reference_calls = _direct_calls(pair["reference"], base)
    candidate_calls = _direct_calls(pair["candidate"], base)

    symbol_by_target: dict[int, str] = {}
    for relocation in pair["relocation_resolutions"]:
        if relocation["type"] != pair["matcher"].REL32 or relocation.get("target_rva") is None:
            continue
        callsite = base + relocation["offset"] - 1
        match = next((item for item in candidate_calls if item[0] == callsite), None)
        if match and relocation.get("target"):
            symbol_by_target[match[1]] = relocation["target"]

    _, public_by_name = pair["matcher"].public_maps(pair["inventory"], pair["pe"])
    publics_by_target: dict[int, list[str]] = {}
    for name, rva in public_by_name.items():
        publics_by_target.setdefault(pair["pe"].image_base + rva, []).append(name)
    procedures_by_target: dict[int, list[str]] = {}
    for procedure in pair["inventory"].get("procedures", ()):
        name = procedure.get("name")
        if not name:
            continue
        target = pair["pe"].image_base + pair["pe"].rva(
            procedure["section"], procedure["offset"],
        )
        procedures_by_target.setdefault(target, []).append(name)

    calls_by_target: dict[int, list[tuple[int, int | None]]] = {}
    # A call is internal only when it lands inside the calling side's own
    # bytes; the candidate may be longer than the reference and reach the
    # reference's next function.
    for code, calls in ((pair["reference"], reference_calls),
                        (pair["candidate"], candidate_calls)):
        for callsite, target, count in calls:
            if base <= target < base + len(code):
                continue
            calls_by_target.setdefault(target, []).append((callsite, count))

    reference_contracts, candidate_contracts = [], []
    for target, callsites in sorted(calls_by_target.items()):
        symbol = symbol_by_target.get(target)
        if symbol is None:
            # Public names are decorated linker identities. Local procedures
            # have no linker symbol, so use their stable PDB name only when no
            # public exists at the address.
            names = sorted(publics_by_target.get(target, ()))
            if not names:
                names = sorted(set(procedures_by_target.get(target, ())))
            symbol = names[0] if names else f"address@{target:08x}"
        contract, record = pdb_call_target(pair, target, symbol)
        if contract.frontend_issues:
            fallback = _untyped_call_target(target, symbol, callsites)
            if not fallback.frontend_issues:
                contract, record = fallback, None
        if contract.signature and contract.signature.variadic:
            fixed = len(contract.signature.parameters)
            counts = tuple(
                (callsite, count if count is not None and count >= fixed else fixed)
                for callsite, count in callsites
            )
            contract = replace(
                contract,
                argument_count=max((count for _, count in counts), default=fixed),
                callsite_argument_counts=counts,
            )
        reference_contract = candidate_contract = contract
        if record is not None and contract.signature and not contract.frontend_issues:
            try:
                prologue = pair["pe"].read(target - pair["pe"].image_base, 3) == FRAME_PROLOGUE
            except Exception:
                prologue = False
            reference_homes, candidate_homes, issues = entry_homes(
                pair, record, contract.signature, prologue,
                _candidate_record_for(pair, record, symbol),
                # The candidate callee body is not extracted; VC8 frames
                # recorded with a frame pointer begin with the standard
                # prologue.
                True,
            )
            # A callee whose candidate declaration differs cannot be modeled
            # consistently on both sides.
            issues = tuple(
                f"UNMODELED_CALLEE_{issue}" if issue.startswith("CANDIDATE_SIGNATURE_MISMATCH")
                else issue
                for issue in issues
            )
            reference_contract = replace(
                contract, entry_homes=reference_homes, frontend_issues=issues,
            )
            candidate_contract = replace(
                contract, entry_homes=candidate_homes, frontend_issues=issues,
            )
        reference_contracts.append(reference_contract)
        candidate_contracts.append(candidate_contract)
    return tuple(reference_contracts), tuple(candidate_contracts)


def global_object_contracts(pair: dict) -> tuple[MemoryObjectContract, ...]:
    """Return PDB-owned globals touched by the candidate's relocations.

    Interior symbols are folded back into their containing typed PDB object,
    preserving the base-object-plus-offset identity required by the model.
    """
    publics, _ = pair["matcher"].public_maps(pair["inventory"], pair["pe"])
    owners = pair["matcher"].load_target_data_owners(
        pair["build"], pair["pdb"], pair["tool"], pair["inventory"],
        pair["pe"], publics, False,
    )
    relevant = {
        relocation["target_rva"]
        for relocation in pair["relocation_resolutions"]
        if (relocation.get("target_rva") is not None and
            relocation["type"] not in (
                pair["matcher"].REL32, pair["matcher"].SECREL,
            ))
    }
    selected: dict[tuple[int, int], tuple[str, bytes | None]] = {}
    for rva in relevant:
        containing = [
            owner for owner in owners
            if owner["rva"] <= rva < owner["rva"] + owner["size"]
        ]
        if not containing:
            continue
        # Prefer the narrowest typed owner when the PDB exposes overlapping
        # aliases; exact-base aliases of equal size are already grouped.
        owner = min(containing, key=lambda item: (item["size"], item["rva"]))
        logical_id = owner["names"][0] if owner["names"] else f"rva@{owner['rva']:x}"
        selected[(owner["rva"], owner["size"])] = (logical_id, None)

    # Compiler literals have no PDB data record. Include their immutable
    # bytes, including literals assigned a synthetic address because their
    # content does not occur in the target image.
    for relocation in pair["relocation_resolutions"]:
        rva = relocation.get("target_rva")
        literal = (
            _literal_bytes(pair["matcher"], pair["coff"], relocation) or
            _relocated_pointer_table_bytes(
                pair["matcher"], pair["pe"], pair["coff"], relocation,
            ) or
            _named_constant_bytes(pair["coff"], relocation)
        )
        if rva is None or literal is None:
            continue
        selected[(rva, len(literal))] = (
            relocation.get("target") or f"literal@{rva:x}", literal,
        )

    # PDB-absent local statics still have authoritative type/size information
    # in the candidate PDB. Their target identity was established by the
    # unique in-function use-shape match during relocation.
    for relocation in pair["relocation_resolutions"]:
        rva = relocation.get("target_rva")
        size = relocation.get("candidate_object_size")
        if rva is None or not isinstance(size, int) or size <= 0:
            continue
        if relocation["type"] == pair["matcher"].SECREL:
            continue
        if any(start <= rva < start + width for start, width in selected):
            continue
        selected[(rva, size)] = (
            relocation.get("target") or f"candidate_static@{rva:x}", None,
        )

    # Some PDB-absent globals are nevertheless addressed directly after COFF
    # relocation. Model those addresses as shared symbolic storage. Distinct
    # addresses remain distinct objects, and typed owners above take priority.
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    for code in (pair["reference"], pair["candidate"]):
        for instruction in engine.disasm(code, pair["address"]):
            for operand in instruction.operands:
                if operand.type != capstone.x86_const.X86_OP_MEM:
                    continue
                memory = operand.mem
                if (memory.base != capstone.x86_const.X86_REG_INVALID or
                        memory.index != capstone.x86_const.X86_REG_INVALID or
                        memory.segment != capstone.x86_const.X86_REG_INVALID):
                    continue
                address = memory.disp & 0xFFFFFFFF
                rva = address - pair["pe"].image_base
                if not any(
                    section.virtual_address <= rva <
                    section.virtual_address + section.virtual_size
                    for section in pair["pe"].sections
                ):
                    continue
                if any(start <= rva < start + size for start, size in selected):
                    continue
                size = max(1, operand.size)
                selected[(rva, size)] = (f"absolute@{rva:x}", None)

    # Reference-only string literals are visible as immediate image
    # addresses. Give call summaries readable backing for those constants.
    image_start = pair["pe"].image_base
    image_end = image_start + max(
        section.virtual_address + section.virtual_size
        for section in pair["pe"].sections
    )
    for instruction in engine.disasm(pair["reference"], pair["address"]):
        for operand in instruction.operands:
            if operand.type != capstone.x86_const.X86_OP_IMM:
                continue
            address = operand.imm & 0xFFFFFFFF
            if not image_start <= address < image_end:
                continue
            rva = address - image_start
            if any(start <= rva < start + size for start, size in selected):
                continue
            try:
                raw = pair["pe"].read(rva, 64)
            except Exception:
                continue
            end = raw.find(b"\0")
            if end < 0:
                continue
            content = raw[:end + 1]
            if content and all(
                byte in b"\t\r\n" or 0x20 <= byte < 0x7f or byte == 0
                for byte in content
            ):
                selected[(rva, len(content))] = (
                    f"target_literal@{rva:x}", content,
                )
    owner_types = _target_owner_types(pair)
    contracts = [
        MemoryObjectContract(
            name, pair["pe"].image_base + rva, size, content,
            owner_types.get((rva, size)) if content is None else None,
        )
        for (rva, size), (name, content) in sorted(selected.items())
    ]
    tls_relocations = [
        item for item in pair["relocation_resolutions"]
        if item["type"] == pair["matcher"].SECREL
    ]
    if tls_relocations:
        tls_index = next((
            item for item in pair["relocation_resolutions"]
            if item.get("target") == "__tls_index" and
               item.get("target_rva") is not None
        ), None)
        if tls_index is not None:
            contracts = [
                item for item in contracts
                if not (item.address <= pair["pe"].image_base + tls_index["target_rva"] <
                        item.address + item.size)
            ]
            contracts.append(MemoryObjectContract(
                "__tls_index",
                pair["pe"].image_base + tls_index["target_rva"], 4,
                struct.pack("<I", 0),
            ))
        contracts.extend((
            MemoryObjectContract(
                "__tls_array", TLS_ARRAY_POINTER, 4,
                struct.pack("<I", TLS_ARRAY_BASE),
            ),
            MemoryObjectContract(
                "tls_module_slot", TLS_ARRAY_BASE, 4,
                struct.pack("<I", TLS_BLOCK_BASE),
            ),
        ))
        for relocation in tls_relocations:
            offset = struct.unpack_from(
                "<I", pair["candidate"], relocation["offset"],
            )[0]
            size = relocation.get("candidate_object_size") or 4
            contracts.append(MemoryObjectContract(
                relocation.get("target") or f"tls@{offset:x}",
                TLS_BLOCK_BASE + offset, size,
            ))
    unique = {(item.address, item.size): item for item in contracts}
    return tuple(unique[key] for key in sorted(unique))


def _target_type_db(pair: dict):
    return type_database(pair["matcher"], pair["tool"], pair["pdb"])


def _target_owner_types(pair: dict) -> dict[tuple[int, int], int]:
    """Map each typed target global's (rva, size) to its unique PDB type."""
    matcher, pe = pair["matcher"], pair["pe"]
    db = _target_type_db(pair)
    types: dict[tuple[int, int], set[int]] = {}
    records = list(pair["inventory"].get("data_symbols", ()))
    for values in matcher.load_globals(pair["build"], pair["pdb"], pair["tool"], False).values():
        records.extend(values)
    for record in records:
        type_index = record.get("type")
        try:
            rva = pe.rva(record["section"], record["offset"])
        except Exception:
            continue
        size = matcher.type_size(db, type_index)
        if size:
            types.setdefault((rva, size), set()).add(type_index)
    return {key: next(iter(values)) for key, values in types.items() if len(values) == 1}


SIMPLE_CHARACTER_TYPES = {0x10, 0x20, 0x68, 0x69, 0x70}


def type_placements(pair: dict):
    """PDB layout-directed interior placements for the alias model.

    An object of the inner type may lie at every offset where the outer
    type's layout (members, base classes, array elements, recursively)
    contains a compatible type. Character and void pointees may address any
    byte. Unknown types return None so the alias model considers every
    aligned offset.
    """
    matcher = pair["matcher"]
    db = _target_type_db(pair)
    memo: dict[int, dict[tuple, frozenset[int]]] = {}

    def canonical(index):
        index = matcher.strip_qualifiers(db, index)
        return matcher.resolve_forward_ref(db, index) if index is not None and index >= 0x1000 else index

    def shape(index) -> tuple | None:
        """A compatibility key: MSVC does not use type-based alias analysis,
        so same-sized scalars of one class, and all pointers, are compatible."""
        index = canonical(index)
        if index is None:
            return None
        if index < 0x1000:
            if matcher.simple_pointer_base(index) is not None:
                return ("pointer",)
            size = matcher.type_size(db, index)
            real = (index & 0xFF) in (0x40, 0x41, 0x42)
            return ("real" if real else "integer", size)
        record = db.get(index) or {}
        kind = record.get("Kind")
        if kind == "LF_POINTER":
            return ("pointer",)
        if kind == "LF_ENUM":
            return shape(record["Enum"].get("UnderlyingType"))
        return ("record", index)

    def contained(index) -> dict[tuple, frozenset[int]]:
        """Offsets of every type shape occurring inside ``index``."""
        index = canonical(index)
        if index in memo:
            return memo[index]
        memo[index] = {}
        result: dict[tuple, set[int]] = {}
        own = shape(index)
        if own is not None:
            result.setdefault(own, set()).add(0)
        record = db.get(index) if index is not None and index >= 0x1000 else None
        kind = (record or {}).get("Kind")
        children: list[tuple[int, int | None]] = []
        if kind == "LF_ARRAY":
            element = record["Array"].get("ElementType")
            element_size = matcher.type_size(db, element)
            total = matcher.type_size(db, index)
            if element_size and total:
                children.extend((offset, element) for offset in range(0, total, element_size))
        elif kind in matcher.CLASS_LIKE_KINDS or kind == "LF_UNION":
            body = record["Union" if kind == "LF_UNION" else "Class"]
            for _, offset, member in matcher.members_of(db, body.get("FieldList")) or ():
                children.append((offset, member))
        nested_cache: dict[int | None, dict[tuple, frozenset[int]]] = {}
        for offset, child in children:
            if child not in nested_cache:
                nested_cache[child] = contained(child)
            for key, offsets in nested_cache[child].items():
                result.setdefault(key, set()).update(offset + item for item in offsets)
        memo[index] = {key: frozenset(values) for key, values in result.items()}
        return memo[index]

    def placements(outer_type, outer_size, inner_type, inner_size):
        if outer_type is None or inner_type is None:
            return None
        inner = canonical(inner_type)
        if inner is not None and inner < 0x1000 and (
                (inner & 0xFF) in SIMPLE_CHARACTER_TYPES or (inner & 0xFF) == 0x03):
            return tuple(range(0, max(outer_size - inner_size + 1, 0)))
        key = shape(inner)
        if key is None:
            return None
        return tuple(sorted(contained(outer_type).get(key, ())))

    return placements


_CANDIDATE_INDEXES: dict[str, dict] = {}


def _candidate_procedure_index(pair: dict) -> dict:
    """Candidate PDB procedures grouped by object and public symbol, built
    once per process (path normalization per record was the dominant cost)."""
    candidate_pdb = candidate_pdb_path(pair["build"])
    key = normalized_path(candidate_pdb)
    if key not in _CANDIDATE_INDEXES:
        inventory = pair["matcher"].load_inventory(
            pair["build"], candidate_pdb, pair["tool"], False,
        )
        by_object: dict[str, list[dict]] = {}
        by_public: dict[str, list[dict]] = {}
        for item in inventory.get("procedures", ()):
            by_object.setdefault(normalized_path(item.get("object") or ""), []).append(item)
            for symbol in item.get("public_symbols") or ():
                by_public.setdefault(symbol, []).append(item)
        _CANDIDATE_INDEXES[key] = {
            "inventory": inventory, "by_object": by_object, "by_public": by_public,
        }
    return _CANDIDATE_INDEXES[key]


def candidate_pdb_path(build: Path) -> Path:
    return build / "src" / "win32" / "iw4_multiplayer.pdb"


def candidate_procedure_record(pair: dict) -> dict | None:
    """The candidate PDB procedure record for the extracted candidate body."""
    candidate_pdb = candidate_pdb_path(pair["build"])
    if not candidate_pdb.is_file():
        return None
    matches = list(
        _candidate_procedure_index(pair)["by_object"].get(normalized_path(pair["object"]), ())
    )
    symbol = pair["record"].get("candidate_symbol")
    if symbol:
        matches = [item for item in matches if symbol in (item.get("public_symbols") or ())]
    else:
        matches = [
            item for item in matches
            if item.get("name") == pair["record"].get("name") and
            item.get("size") == len(pair["candidate"])
        ]
    return matches[0] if len(matches) == 1 else None


# push ebp; mov ebp, esp: EBP is the entry ESP minus the saved EBP slot.
FRAME_PROLOGUE = b"\x55\x8b\xec"


def stack_allocation_contracts(pair: dict):
    """Logical stack objects shared by both frames, from both PDBs.

    A local is modeled only when both procedures are EBP-framed, both PDB
    records are fully understood, and it has one unique, non-overlapping
    home of the same size on each side. Other escaping stack storage keeps
    the conservative extent model.
    """
    from angr_equiv import LogicalAllocation, STACK_BASE
    from pdb_frontend import frame_layout

    candidate_record = candidate_procedure_record(pair)
    if candidate_record is None:
        return (), ()
    matcher, tool = pair["matcher"], pair["tool"]
    layouts = (
        frame_layout(matcher, tool, pair["pdb"],
                     _procedure_metadata_record(pair["inventory"], pair["record"])),
        frame_layout(matcher, tool, candidate_pdb_path(pair["build"]), candidate_record),
    )
    codes = (pair["reference"], pair["candidate"])
    if any(not layout.complete or not code.startswith(FRAME_PROLOGUE)
           for layout, code in zip(layouts, codes, strict=True)):
        return (), ()
    frame_base = STACK_BASE - 4
    sides: list[dict[str, tuple[int, int]]] = []
    for layout in layouts:
        names = [item.name for item in layout.locals]
        sides.append({
            f"local:{item.name}": (frame_base + item.frame_offset, item.size)
            for item in layout.locals
            # Parameters (positive offsets) may be homed per a custom
            # register convention; only frame locals are correlated here.
            if item.frame_offset < 0 and names.count(item.name) == 1
        })
    common = [
        key for key in sides[0]
        if key in sides[1] and sides[0][key][1] == sides[1][key][1]
    ]

    def overlapping(side: dict[str, tuple[int, int]], key: str) -> bool:
        start, size = side[key]
        return any(
            other != key and start < side[other][0] + side[other][1] and
            side[other][0] < start + size
            for other in side
        )

    kept = [key for key in common if not any(overlapping(side, key) for side in sides)]
    return tuple(
        tuple(LogicalAllocation(key, side[key][0], side[key][1]) for key in sorted(kept))
        for side in sides
    )


def pointer_global_contracts(pair: dict) -> tuple[PointerGlobalContract, ...]:
    """Pointer-valued global slots whose pointees require finite scenarios."""
    result: dict[int, PointerGlobalContract] = {}
    for relocation in pair["relocation_resolutions"]:
        rva = relocation.get("target_rva")
        size = relocation.get("candidate_pointer_pointee_size")
        if rva is None or not isinstance(size, int) or size <= 0:
            continue
        if relocation["type"] == pair["matcher"].SECREL:
            offset = struct.unpack_from(
                "<I", pair["candidate"], relocation["offset"],
            )[0]
            address = TLS_BLOCK_BASE + offset
        else:
            address = pair["pe"].image_base + rva
        result[address] = PointerGlobalContract(
            relocation.get("target") or f"pointer_global@{rva:x}",
            address, size,
        )
    return tuple(result[address] for address in sorted(result))


def load_matcher(repository: Path):
    tools = repository / "tools" / "byte_match"
    sys.path.insert(0, str(tools))
    spec = importlib.util.spec_from_file_location("artifact_matcher", tools / "iw4match.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load matcher module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def disassemble(code: bytes, address: int) -> list[str]:
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return [f"{ins.address:08x}: {ins.mnemonic:<8} {ins.op_str}" for ins in engine.disasm(code, address)]


def _literal_bytes(matcher, coff: dict, relocation: dict) -> bytes | None:
    symbol = relocation.get("target") or ""
    if symbol.startswith("??_C@"):
        # iw4match's generic literal helper intentionally caps reads at 64
        # bytes. Assertion paths routinely exceed that, so recover the whole
        # NUL-terminated compiler string directly from its COFF section.
        record = relocation.get("target_record")
        section = next((
            item for item in coff["canonical"]["sections"]
            if record and item["index"] == record["section"]
        ), None)
        if not record or not section:
            return None
        data = bytes.fromhex(section["bytes"])
        addend = struct.unpack_from("<i", coff["bytes"], relocation["offset"])[0]
        start = record["value"] + addend
        if start < 0 or start >= len(data):
            return None
        end = data.find(b"\0", start)
        return data[start:end + 1] if end >= 0 else None
    value = matcher.candidate_literal(coff, relocation)
    if not value:
        return None
    if symbol.startswith("__real@"):
        encoded = symbol.removeprefix("__real@")
        width = len(encoded) // 2
        return value[:width] if width in (4, 8, 10, 16) else None
    if symbol.startswith(("__xmm@", "__ymm@")):
        return value[:16 if symbol.startswith("__xmm@") else 32]
    return None


def _named_constant_bytes(coff: dict, relocation: dict) -> bytes | None:
    """Recover a source-named read-only constant from its COFF symbol extent."""
    symbol = relocation.get("target") or ""
    undecorated = symbol.lstrip("_").split("@", 1)[0].lstrip("?")
    if not undecorated.startswith("k"):
        return None
    record = relocation.get("target_record")
    section = next((
        item for item in coff["canonical"]["sections"]
        if record and item["index"] == record["section"]
    ), None)
    if not record or not section:
        return None
    data = bytes.fromhex(section["bytes"])
    start = record["value"]
    following = [
        item["value"] for item in coff["canonical"]["symbols"]
        if item.get("section") == record["section"] and item.get("value", -1) > start
    ]
    end = min(following, default=len(data))
    if not start <= end <= len(data) or not 0 < end - start <= 4096:
        return None
    if any(start <= item["offset"] < end for item in section.get("relocations", ())):
        return None
    value = data[start:end]
    nul = value.find(b"\0")
    if nul >= 0 and value[:nul] and all(
        byte in b"\t\r\n" or 0x20 <= byte < 0x7f for byte in value[:nul]
    ):
        value = value[:nul + 1]
    return value or None


def _relocated_pointer_table_bytes(matcher, pe, coff: dict,
                                   relocation: dict) -> bytes | None:
    """Materialize a typed constant pointer table using target literals."""
    size = relocation.get("candidate_object_size")
    record = relocation.get("target_record")
    if not record or not size or size % 4 or size > 4096:
        return None
    section = next((
        item for item in coff["canonical"]["sections"]
        if item["index"] == record.get("section")
    ), None)
    if section is None:
        return None
    data = bytes.fromhex(section["bytes"])
    start = record["value"]
    relocations = {
        item["offset"]: item for item in section.get("relocations", ())
        if start <= item["offset"] < start + size
    }
    if set(relocations) != set(range(start, start + size, 4)):
        return None
    symbols = {item["index"]: item for item in coff["canonical"]["symbols"]}
    result = bytearray()
    try:
        for offset in range(start, start + size, 4):
            item = relocations[offset]
            if item["type"] != matcher.DIR32:
                return None
            symbol = symbols[item["symbol_index"]]
            if not (symbol.get("name") or "").startswith("??_C@"):
                return None
            literal_section = next(
                value for value in coff["canonical"]["sections"]
                if value["index"] == symbol["section"]
            )
            literal_data = bytes.fromhex(literal_section["bytes"])
            addend = struct.unpack_from("<i", data, offset)[0]
            literal_start = symbol["value"] + addend
            literal_end = literal_data.find(b"\0", literal_start)
            if literal_start < 0 or literal_end < literal_start:
                return None
            literal = literal_data[literal_start:literal_end + 1]
            target_rva = _find_content_rva(pe, literal)
            if target_rva is None:
                target_rva = _synthetic_rva(pe, b"constant\0" + literal)
            result.extend(struct.pack("<I", pe.image_base + target_rva))
    except (KeyError, StopIteration, struct.error, ValueError):
        return None
    return bytes(result)


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def _section_characteristics(pe) -> list[int]:
    headers = pe.optional_header + pe.optional_size
    return [
        struct.unpack_from("<I", pe.data, headers + number * 40 + 36)[0]
        for number in range(len(pe.sections))
    ]


def _find_content_rva(pe, content: bytes) -> int | None:
    """Locate an immutable constant by content in read-only image data.

    Code and writable data are excluded: equal bytes there are not the same
    constant. A NUL-terminated string must start at a string boundary, not
    at the tail of a longer string.
    """
    string = content.endswith(b"\0") and b"\0" not in content[:-1]
    matches: list[int] = []
    for section, characteristics in zip(pe.sections, _section_characteristics(pe), strict=True):
        if characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE):
            continue
        raw = pe.data[section.raw_offset:section.raw_offset + section.raw_size]
        start = 0
        while True:
            offset = raw.find(content, start)
            if offset < 0:
                break
            if not string or offset == 0 or raw[offset - 1] == 0:
                matches.append(section.virtual_address + offset)
            start = offset + 1
    return min(matches) if matches else None


def _relocation_instruction_matches(
    candidate: bytes, reference: bytes, base: int, offset: int,
) -> bool:
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True

    def containing(code: bytes):
        return next((
            instruction for instruction in engine.disasm(code, base)
            if instruction.address - base <= offset <
               instruction.address - base + instruction.size
        ), None)

    left = containing(candidate)
    right = containing(reference)
    if left is None or right is None:
        return False
    return (
        left.address == right.address and left.size == right.size and
        left.mnemonic == right.mnemonic and
        tuple(item.type for item in left.operands) ==
        tuple(item.type for item in right.operands)
    )


def _field_signature(instruction, field_address: int) -> tuple | None:
    relative = field_address - instruction.address
    operand_types = tuple(item.type for item in instruction.operands)
    if instruction.imm_size == 4 and relative == instruction.imm_offset:
        return (instruction.mnemonic, operand_types, "imm")
    if instruction.disp_size == 4 and relative == instruction.disp_offset:
        return (instruction.mnemonic, operand_types, "disp")
    return None


def _local_static_target_rva(
    matcher, pe, coff: dict, reference: bytes, function_rva: int, symbol: str,
) -> int | None:
    """Resolve a PDB-absent local static by all of its in-function use shapes."""
    base = pe.image_base + function_rva
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    candidate_instructions = list(engine.disasm(coff["bytes"], base))
    reference_instructions = list(engine.disasm(reference, base))

    expected: Counter = Counter()
    for relocation in coff["relocations"]:
        if relocation.get("target") != symbol or relocation["type"] != matcher.DIR32:
            continue
        field_address = base + relocation["offset"]
        instruction = next((
            item for item in candidate_instructions
            if item.address <= field_address < item.address + item.size
        ), None)
        signature = _field_signature(instruction, field_address) if instruction else None
        if signature is None:
            return None
        expected[signature] += 1
    if not expected:
        return None

    uses: dict[int, Counter] = {}
    for instruction in reference_instructions:
        fields: list[tuple[int, str]] = []
        if instruction.imm_size == 4:
            fields.append((instruction.imm_offset, "imm"))
        if instruction.disp_size == 4:
            fields.append((instruction.disp_offset, "disp"))
        for field_offset, kind in fields:
            raw = struct.unpack_from(
                "<I", reference, instruction.address - base + field_offset,
            )[0]
            rva = raw - pe.image_base
            if not any(
                section.virtual_address <= rva <
                section.virtual_address + section.virtual_size
                for section in pe.sections
            ):
                continue
            signature = (
                instruction.mnemonic,
                tuple(item.type for item in instruction.operands), kind,
            )
            uses.setdefault(rva, Counter())[signature] += 1

    matches = [rva for rva, signatures in uses.items() if signatures == expected]
    return matches[0] if len(matches) == 1 else None


def _relocated_pointer_table_target_rva(
    matcher, pe, coff: dict, reference: bytes, function_rva: int,
    relocation: dict,
) -> int | None:
    """Validate a candidate string-pointer table against target contents."""
    size = relocation.get("candidate_object_size")
    record = relocation.get("target_record")
    if not record or not size or size % 4 or size > 4096:
        return None
    section = next((
        item for item in coff["canonical"]["sections"]
        if item["index"] == record.get("section")
    ), None)
    if section is None:
        return None
    section_data = bytes.fromhex(section["bytes"])
    start = record["value"]
    if start < 0 or start + size > len(section_data):
        return None
    table_relocations = {
        item["offset"]: item for item in section.get("relocations", ())
        if start <= item["offset"] < start + size
    }
    if set(table_relocations) != set(range(start, start + size, 4)):
        return None
    symbols = {
        item["index"]: item for item in coff["canonical"]["symbols"]
    }
    base = pe.image_base + function_rva
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    candidate_instruction = next((
        item for item in engine.disasm(coff["bytes"], base)
        if item.address <= base + relocation["offset"] < item.address + item.size
    ), None)
    candidate_signature = (
        _field_signature(candidate_instruction, base + relocation["offset"])
        if candidate_instruction else None
    )
    if candidate_signature is None:
        return None
    function_addend = struct.unpack_from(
        "<i", coff["bytes"], relocation["offset"],
    )[0]

    def validates(table_rva: int) -> bool:
        try:
            pe.read(table_rva, size)
        except Exception:
            return False
        try:
            for relative in range(0, size, 4):
                table_item = table_relocations[start + relative]
                if table_item["type"] != matcher.DIR32:
                    return False
                symbol = symbols.get(table_item["symbol_index"])
                if not symbol or not (symbol.get("name") or "").startswith("??_C@"):
                    return False
                literal_section = next(
                    item for item in coff["canonical"]["sections"]
                    if item["index"] == symbol.get("section")
                )
                literal_data = bytes.fromhex(literal_section["bytes"])
                item_addend = struct.unpack_from("<i", section_data, start + relative)[0]
                literal_start = symbol["value"] + item_addend
                literal_end = literal_data.find(b"\0", literal_start)
                if literal_start < 0 or literal_end < literal_start:
                    return False
                literal = literal_data[literal_start:literal_end + 1]
                target_pointer = struct.unpack(
                    "<I", pe.read(table_rva + relative, 4),
                )[0]
                target_literal_rva = target_pointer - pe.image_base
                if pe.read(target_literal_rva, len(literal)) != literal:
                    return False
        except Exception:
            return False
        return True

    matches: list[int] = []
    try:
        for instruction in engine.disasm(reference, base):
            for field_offset in (instruction.imm_offset, instruction.disp_offset):
                if not field_offset:
                    continue
                field_address = instruction.address + field_offset
                if _field_signature(instruction, field_address) != candidate_signature:
                    continue
                raw = struct.unpack_from(
                    "<I", reference, field_address - base,
                )[0]
                table_rva = raw - pe.image_base - function_addend
                if validates(table_rva):
                    matches.append(table_rva)
    except (KeyError, StopIteration, struct.error, ValueError):
        return None
    return matches[0] if len(set(matches)) == 1 else None


def _target_symbol_rva(
    matcher, repository: Path, inventory: dict, pe, owner: dict,
    coff: dict, relocation: dict, public_by_name: dict[str, int],
    target_data_rvas: dict[str, int], target_function_rvas: dict[str, int],
    reference: bytes, target_data_owners: tuple[dict, ...],
    provenance: dict | None = None,
) -> int:
    symbol = relocation.get("target")
    if not symbol:
        raise RelocationResolutionError("relocation has no target symbol")
    if symbol == "__tls_array":
        raise RelocationResolutionError("__tls_array is a literal, not an RVA")

    # A PDB public is authoritative. Reviewed raw maps exist specifically for
    # PDB-absent storage/functions and must not compete with a real identity.
    if symbol in public_by_name:
        return public_by_name[symbol]
    candidates: set[int] = set()
    reviewed_function = matcher.target_function_rva(symbol, target_function_rvas)

    for item in inventory.get("procedures", []):
        if (item.get("object") == owner.get("object") and
                item.get("source") == owner.get("source") and
                item.get("name") and matcher.local_name_matches(symbol, item["name"])):
            candidates.add(pe.rva(item["section"], item["offset"]))
    for item in inventory.get("data_symbols", []):
        if (item.get("object") == owner.get("object") and
                item.get("source") == owner.get("source") and
                item.get("name") and matcher.local_name_matches(symbol, item["name"])):
            candidates.add(pe.rva(item["section"], item["offset"]))

    # COMDATs and private definitions can be emitted into a different object
    # than the procedure that references them. A unique program-wide PDB
    # identity is still authoritative; ambiguous names remain unresolved.
    if not candidates:
        global_candidates = {
            pe.rva(item["section"], item["offset"])
            for collection in (
                inventory.get("procedures", []),
                inventory.get("data_symbols", []),
            )
            for item in collection
            if item.get("name") and matcher.local_name_matches(symbol, item["name"])
        }
        if len(global_candidates) == 1:
            candidates.update(global_candidates)

    if not candidates and reviewed_function is not None:
        candidates.add(reviewed_function)
    if not candidates and symbol in target_data_rvas:
        candidates.add(target_data_rvas[symbol])

    if not candidates and relocation.get("type") == matcher.DIR32:
        local_static = _local_static_target_rva(
            matcher, pe, coff, reference, owner["target_rva"], symbol,
        )
        if local_static is not None:
            candidates.add(local_static)

    if not candidates and relocation.get("type") == matcher.DIR32:
        pointer_table = _relocated_pointer_table_target_rva(
            matcher, pe, coff, reference, owner["target_rva"], relocation,
        )
        if pointer_table is not None:
            candidates.add(pointer_table)

    # A private candidate symbol may represent an address inside a differently
    # named target global. When the relocation field belongs to the same
    # instruction shape on both sides, use the target field as an address hint
    # only if the PDB proves ownership of that exact/interior address.
    if (not candidates and relocation.get("type") != matcher.SECREL and
            _relocation_instruction_matches(
                coff["bytes"], reference, pe.image_base + owner["target_rva"],
                relocation["offset"],
            )):
        try:
            effective_rva = matcher.target_ref(
                pe, owner["target_rva"], reference,
                relocation["offset"], relocation["type"],
            )
        except Exception:
            effective_rva = None
        if effective_rva is not None and any(
            item["rva"] <= effective_rva < item["rva"] + item["size"]
            for item in target_data_owners
        ):
            addend = struct.unpack_from("<i", coff["bytes"], relocation["offset"])[0]
            candidates.add(effective_rva - addend)
            # The identity is borrowed from the reference being compared, so
            # a wrong candidate reference cannot be detected. Callers must
            # not report equivalence that rests on it.
            if provenance is not None:
                provenance["rule"] = "reference_address_hint"

    target_record = relocation.get("target_record")
    if (matcher.JUMP_TABLE_LABEL_RE.match(symbol) and target_record and
            target_record.get("section") == coff.get("function_section")):
        label_offset = target_record["value"] - coff["function_start"]
        if 0 <= label_offset < len(coff["bytes"]):
            return owner["target_rva"] + label_offset

    if not candidates:
        literal = _literal_bytes(matcher, coff, relocation)
        if literal is not None:
            match = _find_content_rva(pe, literal)
            if match is not None:
                return match
            # Preserve differing constants as distinct logical objects. This
            # lets path-sensitive verification decide whether the difference
            # is observable instead of rejecting extraction unconditionally.
            return _synthetic_rva(pe, b"constant\0" + literal)
        relocated_constant = _relocated_pointer_table_bytes(
            matcher, pe, coff, relocation,
        )
        if relocated_constant is not None:
            return _synthetic_rva(
                pe, b"relocated-constant\0" + relocated_constant,
            )
        named_constant = _named_constant_bytes(coff, relocation)
        if named_constant is not None:
            match = _find_content_rva(pe, named_constant) if any(named_constant) else None
            if match is not None:
                return match
            return _synthetic_rva(
                pe, b"constant\0" + named_constant,
            )
    if not candidates and (
        relocation.get("type") == matcher.REL32 or symbol.startswith("__ehhandler$")
    ):
        # Keep unresolved call targets/EH metadata distinct and executable.
        # Their missing ABI or exception contract is reported explicitly by
        # the frontend instead of being mislabeled as extraction failure.
        return _synthetic_rva(pe, b"symbol\0" + symbol.encode("utf-8"))
    if len(candidates) != 1:
        detail = "unresolved" if not candidates else "ambiguous: " + ", ".join(hex(x) for x in sorted(candidates))
        raise RelocationResolutionError(f"{symbol}: {detail}")
    return next(iter(candidates))


def relocate_candidate(
    matcher, repository: Path, inventory: dict, pe, record: dict,
    coff: dict, function_rva: int, target_data_owners: tuple[dict, ...] = (),
) -> tuple[bytes, tuple[dict, ...]]:
    candidate = bytearray(coff["bytes"])
    reference = pe.read(function_rva, record["size"])
    _, public_by_name = matcher.public_maps(inventory, pe)
    target_data_rvas = matcher.load_target_data_rvas(repository / matcher.DEFAULT_TARGET_DATA_RVAS)
    target_function_rvas = matcher.load_target_function_rvas(repository / matcher.DEFAULT_TARGET_FUNCTION_RVAS)
    resolutions: list[dict] = []
    owner = {**record, "target_rva": function_rva}
    for relocation in coff["relocations"]:
        offset = relocation["offset"]
        kind = relocation["type"]
        if offset + 4 > len(candidate):
            raise RelocationResolutionError(f"relocation +0x{offset:x} lies outside function")
        provenance: dict = {}
        if kind == matcher.DIR32 and relocation.get("target") == "__tls_array":
            encoded = 0x2C
            target_rva = None
        else:
            target_rva = _target_symbol_rva(
                matcher, repository, inventory, pe, owner, coff, relocation,
                public_by_name, target_data_rvas, target_function_rvas,
                reference, target_data_owners, provenance,
            )
            addend = struct.unpack_from("<i", coff["bytes"], offset)[0]
            if kind == matcher.REL32:
                encoded = target_rva + addend - (function_rva + offset + 4)
            elif kind == matcher.DIR32:
                encoded = pe.image_base + target_rva + addend
            elif kind == matcher.DIR32NB:
                encoded = target_rva + addend
            elif kind == matcher.SECREL:
                encoded = pe.section_offset(target_rva)[1] + addend
            else:
                raise RelocationResolutionError(
                    f"{relocation.get('target')}: unsupported relocation type 0x{kind:x}"
                )
        struct.pack_into("<I", candidate, offset, encoded & 0xFFFFFFFF)
        resolutions.append({
            **relocation, "target_rva": target_rva,
            **({"identity_rule": provenance["rule"]} if "rule" in provenance else {}),
        })
    return bytes(candidate), tuple(resolutions)


def _find_public_coff_fallback(matcher, build: Path, symbol: str) -> tuple[Path, dict] | None:
    """Find a COMDAT/public body emitted outside its PDB-owned object."""
    needle = symbol.encode("ascii", errors="strict")
    matches: list[tuple[Path, dict]] = []
    for path in build.rglob("*.obj"):
        try:
            if needle not in path.read_bytes():
                continue
            matches.append((path, matcher.coff_function(path, symbol)))
        except Exception:
            continue
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


def _pointer_pointee_size(matcher, db, type_index: int | None) -> int | None:
    index = matcher.strip_qualifiers(db, type_index)
    simple = matcher.simple_pointer_base(index)
    if simple is not None:
        return matcher.type_size(db, simple)
    record = db.get(index) if index is not None else None
    if not record or record.get("Kind") != "LF_POINTER":
        return None
    referent = (record.get("Pointer") or {}).get("ReferentType")
    return matcher.type_size(db, referent)


def _annotate_candidate_data(
    matcher, build: Path, tool: Path, object_path: Path,
    resolutions: tuple[dict, ...],
) -> tuple[dict, ...]:
    candidate_pdb = build / "src" / "win32" / "iw4_multiplayer.pdb"
    if not candidate_pdb.is_file():
        return resolutions
    inventory = matcher.load_inventory(build, candidate_pdb, tool, False)
    globals_by_name = matcher.load_globals(build, candidate_pdb, tool, False)
    db = type_database(matcher, tool, candidate_pdb)
    wanted_object = normalized_path(object_path)
    annotated = []
    for relocation in resolutions:
        symbol = relocation.get("target") or ""
        matches = [
            item for item in inventory.get("data_symbols", ())
            if item.get("name") and matcher.local_name_matches(symbol, item["name"])
        ]
        for name, records in globals_by_name.items():
            if matcher.local_name_matches(symbol, name):
                matches.extend({"name": name, **item} for item in records)
        owned = [
            item for item in matches
            if normalized_path(item.get("object") or "") == wanted_object
        ]
        if len(owned) == 1:
            matches = owned
        if len(matches) == 1:
            type_index = matches[0].get("type")
            size = matcher.type_size(db, type_index)
            pointee_size = _pointer_pointee_size(matcher, db, type_index)
            relocation = {
                **relocation,
                "candidate_object_size": size,
                "candidate_pointer_pointee_size": pointee_size,
            }
        elif not matches:
            decorated_pointer = re.search(r"@@3P[AB]?U([^@]+)@@", symbol)
            if decorated_pointer:
                type_name = decorated_pointer.group(1)
                type_index = db.by_name.get(type_name)
                pointee_size = matcher.type_size(db, type_index)
                if pointee_size:
                    relocation = {
                        **relocation,
                        "candidate_object_size": 4,
                        "candidate_pointer_pointee_size": pointee_size,
                    }
        annotated.append(relocation)
    return tuple(annotated)


def extract(repository: Path, build: Path, pdb: Path, exe: Path, symbol: str):
    matcher = load_matcher(repository)
    tool = matcher.locate_pdbutil(None)
    inventory = matcher.load_inventory(build, pdb, tool, False)
    pe = matcher.PEImage(exe)
    record = matcher.resolve_selector(symbol, inventory, pe)
    object_path = matcher.candidate_path(build, record)
    if record.get("candidate_symbol"):
        try:
            coff = matcher.coff_function(object_path, record["candidate_symbol"])
        except Exception:
            fallback = _find_public_coff_fallback(
                matcher, build, record["candidate_symbol"],
            )
            if fallback is None:
                raise
            object_path, coff = fallback
    else:
        candidates = matcher.coff_local_functions(object_path, record)
        if len(candidates) != 1:
            raise RuntimeError(f"local procedure resolved to {len(candidates)} candidates")
        coff = candidates[0]

    # Candidate type information is needed while resolving relocation-bearing
    # constants (not only after relocation has completed).
    coff = {
        **coff,
        "relocations": _annotate_candidate_data(
            matcher, build, tool, object_path, tuple(coff["relocations"]),
        ),
    }

    rva = pe.rva(record["section"], record["offset"])
    reference = pe.read(rva, record["size"])
    publics, _ = matcher.public_maps(inventory, pe)
    target_data_owners = tuple(matcher.load_target_data_owners(
        build, pdb, tool, inventory, pe, publics, False,
    ))
    candidate, resolutions = relocate_candidate(
        matcher, repository, inventory, pe, record, coff, rva,
        target_data_owners,
    )
    metadata_record = _procedure_metadata_record(inventory, record)
    metadata = extract_function_metadata(
        matcher, tool, pdb, metadata_record,
        tuple(item.get("target") or "" for item in coff["relocations"]),
        build=build, inventory=inventory,
    )

    pair = {
        "matcher": matcher,
        "inventory": inventory,
        "tool": tool,
        "pdb": pdb,
        "build": build,
        "pe": pe,
        "record": record,
        "coff": coff,
        "object": object_path,
        "rva": rva,
        "address": pe.image_base + rva,
        "reference": reference,
        "candidate": candidate,
        "relocation_resolutions": resolutions,
        "signature": metadata.signature,
        "frontend_issues": metadata.issues,
        "typed_symbol_indices": metadata.typed_symbol_indices,
        "reference_homes": None,
        "candidate_homes": None,
    }
    if metadata.signature is not None:
        reference_homes, candidate_homes, issues = entry_homes(
            pair, metadata_record, metadata.signature,
            reference.startswith(FRAME_PROLOGUE), candidate_procedure_record(pair),
            candidate.startswith(FRAME_PROLOGUE),
        )
        pair["reference_homes"] = reference_homes
        pair["candidate_homes"] = candidate_homes
        pair["frontend_issues"] = (*pair["frontend_issues"], *issues)
    return pair


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--pdb", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--symbol", required=True)
    args = parser.parse_args()
    pair = extract(
        args.repository.resolve(), args.build.resolve(), args.pdb.resolve(),
        args.exe.resolve(), args.symbol,
    )

    print(f"symbol: {args.symbol}")
    print(f"object: {pair['object']}")
    print(f"address: 0x{pair['address']:x}")
    print(f"reference bytes: {pair['reference'].hex()}")
    print(f"candidate bytes: {pair['candidate'].hex()}")
    print(f"signature: {pair['signature']}")
    if pair["frontend_issues"]:
        print(f"frontend issues: {', '.join(pair['frontend_issues'])}")
    print("relocations:")
    for relocation in pair["coff"]["relocations"]:
        print(f"  +0x{relocation['offset']:x} type=0x{relocation['type']:x} target={relocation['target']}")
    print("reference disassembly:")
    print("\n".join(f"  {line}" for line in disassemble(pair["reference"], pair["address"])))
    print("candidate disassembly:")
    print("\n".join(f"  {line}" for line in disassemble(pair["candidate"], pair["address"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
