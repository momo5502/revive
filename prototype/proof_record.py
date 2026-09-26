"""Versioned, content-addressed records for reusable semantic proofs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from importlib import metadata
import json
from pathlib import Path
from typing import Any

from angr_equiv import VerificationResult, VerificationStatus


SCHEMA_VERSION = 2
MODEL_VERSION = "angr-relational-v3"
TOOL_PACKAGES = ("angr", "claripy", "pyvex", "z3-solver", "capstone")
IMPLEMENTATION_FILES = (
    "artifact_cache.py",
    "alias_model.py",
    "angr_equiv.py",
    "campaign.py",
    "live_extract.py",
    "pdb_frontend.py",
    "proof_record.py",
)


def tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for package in TOOL_PACKAGES:
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = "missing"
    return versions


def implementation_hash() -> str:
    """Hash the verifier code that can affect a recorded conclusion."""
    digest = hashlib.sha256()
    directory = Path(__file__).resolve().parent
    for name in IMPLEMENTATION_FILES:
        content = (directory / name).read_bytes()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(content).to_bytes(8, "little"))
        digest.update(content)
    return digest.hexdigest()


def _normalize(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, Path):
        return str(value.resolve())
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def proof_fingerprint(
    *,
    symbol: str,
    reference: bytes,
    candidate: bytes,
    reference_relocations: Any = (),
    candidate_relocations: Any = (),
    signature: Any = None,
    memory_model: Any = None,
    options: Any = None,
    assumptions: Any = None,
) -> str:
    payload = _normalize({
        "schema": SCHEMA_VERSION,
        "model_version": MODEL_VERSION,
        "implementation": implementation_hash(),
        "tools": tool_versions(),
        "symbol": symbol,
        "reference": reference,
        "candidate": candidate,
        "reference_relocations": reference_relocations,
        "candidate_relocations": candidate_relocations,
        "signature": signature,
        "memory_model": memory_model,
        "options": options,
        "assumptions": assumptions,
    })
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ProofRecord:
    schema: int
    model_version: str
    fingerprint: str
    symbol: str
    status: str
    tools: dict[str, str]
    implementation: str
    reasons: tuple[str, ...] = ()
    counterexample: tuple[int, ...] | None = None

    @classmethod
    def create(cls, symbol: str, fingerprint: str,
               result: VerificationResult) -> "ProofRecord":
        return cls(
            SCHEMA_VERSION, MODEL_VERSION, fingerprint, symbol,
            result.status.value, tool_versions(), implementation_hash(), result.reasons,
            result.counterexample,
        )

    @property
    def reusable_equivalence(self) -> bool:
        return (
            self.schema == SCHEMA_VERSION and
            self.model_version == MODEL_VERSION and
            self.tools == tool_versions() and
            self.implementation == implementation_hash() and
            self.status == VerificationStatus.EQUIVALENT.value
        )

    def matches(self, fingerprint: str) -> bool:
        return self.reusable_equivalence and self.fingerprint == fingerprint


def write_record(path: Path, record: ProofRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(asdict(record), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def read_record(path: Path) -> ProofRecord:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ProofRecord(
        schema=raw["schema"],
        model_version=raw["model_version"],
        fingerprint=raw["fingerprint"],
        symbol=raw["symbol"],
        status=raw["status"],
        tools=dict(raw["tools"]),
        implementation=raw.get("implementation", ""),
        reasons=tuple(raw.get("reasons", ())),
        counterexample=(
            tuple(raw["counterexample"])
            if raw.get("counterexample") is not None else None
        ),
    )
