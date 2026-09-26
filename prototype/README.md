# Hardened relational prototype

This directory contains the native-Windows angr/Claripy prototype used to
evaluate semantic equivalence before the planned Remill/Alive2 implementation.
It is deliberately fail-closed: only `EQUIVALENT` is a reusable proof result.

## Result states

- `EQUIVALENT`: every modeled input returns on both sides and no observable
  difference is satisfiable.
- `NOT_EQUIVALENT`: a concrete input witnesses a different return domain,
  return value, call trace, or observed memory value.
- `INCONCLUSIVE`: exploration did not finish, a path did not return, or the
  configured execution limit was reached.
- `MODEL_INCOMPLETE`: execution touched an undeclared external memory region
  or control target.
- `UNSUPPORTED`: the function uses a construct intentionally outside the
  current contract, such as atomic instructions or floating-point environment
  manipulation.
- `EXACT_NOW`: campaign extraction produced byte-identical relocated code.
- `EXTRACTION_FAILED`: PE/PDB/COFF identity construction failed before a proof.
- `SOLVER_CRASH`: the isolated worker process exited natively; the
  coordinator records the selector and continues.

Campaign workers reuse read-only artifact and project setup for up to 32
functions (`--tasks-per-worker 1` restores one process per function). Execution
states are never reused. Crashes, hard timeouts and memory-limit kills replace
the worker and affect only its current task. See the root README for benchmarks
and artifact-cache assumptions.

`counterexample()` is retained for the experiments. It returns a witness or
`None` only for conclusive results and raises `IncompleteVerification` for the
other three states. New callers should use `verify_equivalence()` directly.

## Current proof contract

The executor explores all terminal states; there is no terminal-state cap.
Timeout and instruction-step limits are safety limits and produce
`INCONCLUSIVE`, never success. A proof checks equal return domains, values,
ordered decorated-symbol calls and arguments, memory visible before each call,
and explicitly declared output memory.

External calls receive a shared fresh result for each dynamic call event and,
by default, may change every declared external memory region. A call summary
may disable that havoc only when the caller has established that the callee has
no relevant memory effect. Unknown direct or indirect control targets reject
the model.

Every non-stack read must be covered by `initial_memory`; every non-stack write
must be covered by `observed_memory`. Stack-frame addresses around the modeled
stack are private. This makes omitted global or pointed-to memory visible as a
modeling error instead of silently treating it as unconstrained.

The candidate relocation bridge resolves exact PDB public identities first,
then same-compiland local symbols, reviewed PDB-absent maps, immutable literal
contents, and positional jump-table labels. It re-encodes each supported COFF
relocation at its candidate offset. Missing, ambiguous, or unsupported
relocations fail extraction.

`proof_record.py` creates content-addressed records over both code blobs,
relocations, signature, memory model, options, assumptions, model revision,
the verifier implementation hash, and exact dependency versions. Only a
matching `EQUIVALENT` record can be reused.

The PDB frontend extracts the exact CodeView procedure type, return and
parameter types, cdecl/stdcall/fastcall/thiscall convention, typed locals, and
frame-handler metadata. Register arguments and x87 or EDX:EAX returns are
placed and compared from that signature. Supported by-value aggregates use
their raw ABI width. Unresolved or unsupported ABI shapes reject the proof.
`pdb_call_target()` applies the same procedure type to external-call argument
extraction and screens the callee's candidate relocation metadata.

`alias_model.py` lazily enumerates PDB-admitted pointer nullability, alias
partitions, and allocation orders for both function arguments and
pointer-valued globals.
Arguments and globals may alias each other or an existing typed global object.
`verify_under_pdb_aliasing()` proves every generated case and records the
failing case in diagnostics. Its case limit is fail-closed. PDB-proven
`restrict` pointers cannot share a generated allocation.

Native x86 TLS setup is modeled through the TEB TLS-array pointer, module slot,
and the candidate's `SECREL` offset. PDB-absent local static buffers are mapped
only when all relocation use-shapes identify one unique target address; their
size is then recovered from candidate PDB type information. Ambiguity remains
an extraction failure rather than becoming unconstrained memory.

Private objects that escape are declared as `LogicalAllocation` values on each
execution. Their concrete stack offsets may differ; calls, pointer returns, and
pointer-valued output slots compare logical allocation identity plus offset.
Call summaries snapshot and optionally havoc pointed-to bytes, including bytes
inside private stack allocations.

Volatile accesses are represented by their actual ordered reads and writes in
the single-threaded execution model. Incoming x87/SSE environment state is
shared and final environment state is compared. SEH-chain manipulation,
explicit trap instructions, and lock-prefixed atomics are rejected.

## Explicit limitations

- External-call memory summaries and logical private-allocation boundaries are
  still declarations; missing declarations reject the model.
- CodeView does not encode arbitrary source preconditions. In particular, a
  pointer is nullable unless a separate trusted contract says otherwise.
- Windows unwinding and precise implicit hardware-fault behavior are not
  modeled. Concurrent/atomic semantics remain outside the proof contract.
- Floating-point environment state is shared and compared, but individual
  transcendental instructions may need semantic hooks when PyVEX cannot lower
  them. `FSIN` has such a hook; its live-artifact coverage remains under
  investigation.
- Loop equivalence is whatever symbolic exploration and the solver can prove.
  A timeout or step limit yields `INCONCLUSIVE`.

## Validation

Install the pinned native-Windows environment with:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the self-contained hardening regression suite with:

```powershell
.venv\Scripts\python.exe prototype\test_hardening.py -v
```

The `live_*.py` programs additionally exercise real PE/PDB/COFF artifacts and
require their repository, build directory, PDB, and executable arguments.

## Parallel campaign

`campaign.py split` subtracts every recursively discovered exact ledger entry
from the authoritative function inventory and writes `exact.txt`, `inexact.txt`,
`ledger_only.txt`, and `manifest.json`.

`campaign.py run` classifies the inexact list in disposable per-function
processes, with up to `--jobs` children active concurrently. A native Z3/angr
failure therefore loses only one selector rather than breaking the worker pool.
Only the parent process writes `campaign/results.tsv`, using write-then-rename
after every completed function. The TSV contains the selector, status, proof
fingerprint, reasons, counterexample, and elapsed time. Per-status plain-text
selector lists are exported beneath `campaign/results/`. A matching fingerprint
is reused; changed code, relocations, proof model, options, or dependency
versions are rerun automatically.

The runner checks `EXACT_NOW` immediately after relocation, then builds PDB-
typed direct-call summaries, typed global/member identities, pointer-valued
global alias cases, TLS slots, immutable literal objects, and bounded symbolic
table regions before semantic verification. It is fail-closed: unconstrained
pointer-reachable memory, unsupported ABI shapes, or excess alias cases remain
diagnostic instead of being called equivalent.

The execution timeout defaults to 300 seconds per side for each alias scenario.
Indirect calls are recorded as ordered external events with symbolic target and
inferred arguments. See the root `HANDOFF.md` for current live-test findings and
known gaps.
