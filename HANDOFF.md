# Revive handoff

This document records the design decisions, implementation state, experiments,
and unresolved work as of 2026-09-26. It is the starting point for continuing
development.

## Goal and intended workflow

Byte-exact reconstruction is fragile: harmless compiler choices can change
register allocation, instruction selection, scheduling, or private stack
layout. Revive should prove semantic equivalence for functions that cannot be
kept byte exact.

The intended reconstruction workflow is:

1. Trust byte-exact functions and skip them.
2. Run Revive once on each remaining function after an agent has made it as
   exact as practical.
3. Record a content-addressed `EQUIVALENT` result as “near exact.”
4. Re-run only when code, relocations, the model, options, or dependencies
   change.
5. Leave genuinely different functions for further reconstruction work.

Runtime is secondary to soundness. A function taking several minutes is
acceptable because successful results are cached and campaigns can run with
many independent workers on a large machine.

## Agreed semantic contract

Observable behavior includes:

- return value and whether a returning path exists;
- externally visible reads and writes;
- external calls in exact order;
- the same decorated linker symbol for each direct call;
- equal call arguments in the same order;
- indirect call target and arguments;
- globals resolved to the same root object and byte offset;
- volatile accesses as the actual ordered single-threaded memory operations;
- atomic accesses, exceptions/faults, nontermination, and floating-point
  environment in the eventual complete system.

Not independently observable:

- register selection or ABI-preserved register values;
- stack balance;
- private stack-frame layout and dead stack bytes.

The local stack frame is private. If an address escapes through a call, return,
or external store, it is compared as logical allocation identity plus offset,
not by concrete stack address.

Calls are modeled against a shared abstract environment. Matching dynamic call
events get matching fresh results and matching memory effects. A helper is not
special: it is an ordinary call and its identity is its decorated linker
symbol. Where PDB call typing is unavailable, reviewed x86 calling-convention
fallbacks are used.

Exceptions were explicitly deferred because the target barely uses them.
Atomic/concurrent semantics and precise synchronous hardware faults remain
unsupported. Nontermination is not proved in general: bounded symbolic
execution can only return `INCONCLUSIVE` when it cannot establish termination.

## Why the Python prototype exists

The original design was Remill lifting, an ABI wrapper around Remill's machine
state, LLVM inlining/SROA/O3 plus custom normalization, and two-way Alive2
refinement. The historical design is in [`PLAN-OLD.md`](PLAN-OLD.md).

Before building that native stack, we tested a simpler alternative: execute
both relocated x86 functions symbolically with angr/PyVEX, share inputs and
external effects, and ask Claripy/Z3 whether any observable difference is
satisfiable. This was fast to prototype against live artifacts and remains the
current implementation.

Python orchestration is not expected to be the main scaling bottleneck. PDB
parsing and repeated project construction can be cached, but path exploration,
alias cases, and SMT solving dominate. A direct C++ port of the same algorithm
would not remove exponential path or solver costs. If the symbolic model cannot
be made reliable, the Remill/Alive2 route remains the likely successor.

## Repository layout

- `prototype/angr_equiv.py`: x86 execution, semantic hooks, external-call
  summaries, observable-state comparison, and relational alias driver.
- `prototype/live_extract.py`: reconstruction matcher integration, PE/PDB/COFF
  extraction, relocation, symbol/global/constant/TLS resolution, and call
  contracts.
- `prototype/pdb_frontend.py`: CodeView procedure signatures, ABI types, calling
  conventions, qualifiers, and typed-symbol metadata.
- `prototype/alias_model.py`: streamed nullability, alias partitions,
  allocation orders, pointer-valued globals, and global alias scenarios.
- `prototype/proof_record.py`: schema/model/tool/implementation fingerprints
  and reusable proof records.
- `prototype/campaign.py`: inventory split, isolated parallel classification,
  resumable TSV output, and per-status exports.
- `prototype/test_hardening.py`: self-contained regression suite.
- `prototype/live_*.py`: focused live-artifact experiments.
- `prototype/find_live_mismatches.py`: sample discovery helper.
- `requirements.txt`: pinned symbolic-execution dependencies.

## Implemented frontend and relocation behavior

The live frontend reuses the reconstruction project's tested
`artifact_matcher.py`. It resolves a selector through the reference inventory,
finds the candidate COFF function, relocates it to the reference virtual
address, extracts a PDB-derived signature, and returns both raw functions plus
the contracts required by the verifier.

Implemented identity behavior includes:

- exact decorated PDB public symbols;
- stable same-compiland PDB local procedures;
- reviewed fallback mappings for PDB-absent symbols;
- globals canonicalized to root object and byte offset, including member
  symbols that are emitted as separate globals;
- immutable constants matched by contents rather than compiler-generated
  spelling or address;
- relocated pointer tables materialized at synthetic read-only addresses;
- jump-table relocation handling where available;
- native x86 TLS through the TEB TLS array, module slot, and `SECREL` offset;
- unresolved local static buffers recovered only when relocation use-shapes
  identify one unique target and candidate PDB data supplies the size;
- pointer-valued globals included in alias analysis.

External callees do not need candidate function bodies. Direct-call identity
resolution prefers the candidate relocation's decorated symbol, then a PDB
public, then a stable PDB local identity. There are reviewed summaries/fallbacks
for security-cookie helpers, `memset`, AIL calls, `__CIsqrt`, and
`__ftol2_sse`. x87 and EDX:EAX call returns are supported.

## Implemented execution model

Supported 32-bit MSVC conventions are cdecl, stdcall, fastcall, and thiscall.
The PDB signature controls parameter placement and return extraction. Raw-width
ABI values permit supported by-value aggregates without inventing a field
layout.

Both sides receive the same symbolic arguments and ambient incoming registers.
The x87/SSE rounding state and x87 condition state are shared inputs and are
compared at exit. x87 returns and 64-bit EDX:EAX returns are observable.
`FSIN` is represented as an ordered shared semantic operation with equal input
and fresh equal output rather than expanded transcendental arithmetic.

Direct external calls record decorated identity, arguments, visible-memory
snapshot, and pointer-pointee snapshots. Calls receive a fresh shared result
for each dynamic event and conservatively havoc declared external memory and
declared pointees unless the summary says otherwise.

Indirect x86 calls are hooked as external semantic events. The model records
the symbolic target and inferred stack arguments, compares both, supplies a
shared return, havocs declared memory, and applies inferred callee cleanup.
Argument inference currently scans at most eight preceding instructions and is
heuristic.

Private escaped stack allocations are declared as `LogicalAllocation`s and
compared relationally. Non-stack reads must be covered by initial memory and
non-stack writes by observed memory. Bounded symbolic table reads can be
discovered and the function retried with an explicit region. Anything else is
`MODEL_INCOMPLETE`, not unconstrained success.

## Pointer and alias model

The model enumerates PDB-admitted pointer nullability, alias partitions, and
allocation order for pointer parameters and pointer-valued globals. Pointers
may alias each other or eligible existing globals. PDB `restrict` prevents
generated sharing.

Cases are generated lazily to avoid retaining the whole cross-product. There
is no campaign-wide alias deadline; the execution timeout applies separately
to each reference/candidate execution in each case. Garbage collection is
forced periodically to limit accumulation.

An early model admitted any global at least as large as the pointee. One live
function generated 4,047 cases and exhausted roughly 1.9 GB. Eligibility was
tightened to equal extent, reducing that example to roughly 52 cases. This is
still only a size proxy, not true PDB type compatibility, and should be replaced
with a canonical PDB type-compatibility check.

## Campaign behavior

`campaign.py split` recursively reads exact ledgers and subtracts them from the
authoritative function inventory. In the tested snapshot this produced:

- 9,182 exact inventory selectors;
- 6,889 inexact selectors;
- 198 ledger-only selectors;
- no duplicate inventory selectors.

`campaign.py run` checks relocation-adjusted byte identity first. Non-exact
functions are verified semantically. Each function gets a fresh spawned process
so native Z3 assertions or crashes do not break the coordinator. The parent is
the only TSV writer and uses write-then-rename after every completed result.
Results are keyed by a fingerprint over code, relocations, signature, options,
assumptions, model revision, verifier implementation hash, and exact package
versions.

Defaults are:

- at most four workers, bounded by CPU count;
- 300 seconds per execution side and alias scenario;
- 100,000 symbolic execution steps;
- 4,096 alias cases;
- hash ordering for representative sampling.

The latest campaign was cancelled deliberately and all workers were terminated.
Its generated output contains one `INCONCLUSIVE` `fx_draw` row reporting
`Iop_SinF64`; do not treat it as a current baseline. Generated campaign data is
git-ignored and should be regenerated after the known issues below are handled.

## Status meanings

- `EXACT_NOW`: relocated candidate bytes are identical.
- `EQUIVALENT`: all generated modeled cases are equivalent.
- `NOT_EQUIVALENT`: Z3 found an observable mismatch and may provide a witness.
- `INCONCLUSIVE`: timeout, step limit, no returning terminal state, execution
  engine error, or resource exhaustion.
- `MODEL_INCOMPLETE`: unmodeled external memory/control or an incomplete alias
  contract.
- `UNSUPPORTED`: intentionally unsupported ABI/instruction semantics.
- `EXTRACTION_FAILED`: artifact lookup, relocation, identity, or frontend code
  failed before a proof.
- `SOLVER_CRASH`: isolated child exited without a result.

Only `EXACT_NOW` and `EQUIVALENT` are successes. `NOT_EQUIVALENT` means
“different under the current model,” while all other statuses require
investigation and must never be entered into the near-exact ledger.

## Hardening completed during live testing

The initial campaign had high `EXTRACTION_FAILED`, `MODEL_INCOMPLETE`,
`UNSUPPORTED`, and `INCONCLUSIVE` counts. Investigation led to:

- shared incoming register state, removing nondeterministic false mismatches;
- exhaustive terminal-state handling with no silent path cap;
- fail-closed external memory accounting and bounded-table discovery;
- exact-call ordering, argument, memory-snapshot, and fresh-result semantics;
- PDB-derived ABI handling, register arguments, x87 returns, and EDX:EAX;
- pointer aliases involving pointer-valued globals;
- logical escaped-stack allocation comparison;
- TLS relocation and unresolved local-static-buffer support;
- immutable pointer-table materialization;
- direct external calls without requiring candidate bodies;
- indirect-call event modeling;
- shared floating-point environment and an `FSIN` semantic hook;
- disposable worker processes after Z3 4.13 hit a native
  `shared_occs.cpp:119` assertion in an early long run;
- streamed alias scenarios and tighter global eligibility after memory growth;
- a five-minute default timeout.

The self-contained suite had 26 passing tests after these changes. Re-run it
before relying on this handoff because the final live campaign was cancelled
before a fresh end-to-end baseline was established.

## Known issues and open work

1. **`FSIN`/`Iop_SinF64` remains suspect in live code.** The unit test for raw
   `D9 FE` passes, but the last live `fx_draw` result still reached PyVEX's
   unsupported `Iop_SinF64`. The byte-scan hook may not cover an alternate
   address/base, lifted block shape, or execution path. Reproduce and fix this
   before another campaign.

2. **Candidate-less corpus filtering is not actually implemented.** The split
   command has no build argument and currently only subtracts exact ledgers.
   Missing top-level candidate objects are discovered during classification and
   reported as `UNSUPPORTED:MISSING_CANDIDATE_OBJECT`. Change split/run setup to
   filter these entries explicitly; missing functions are not useful proof
   candidates.

3. **Alias-to-global eligibility uses equal byte size.** Carry canonical PDB
   type identity and compatibility into `GlobalObject` and `PointerGlobal` so
   unrelated equal-sized types cannot alias while valid subobjects can.

4. **Indirect-call ABI recovery is heuristic.** Replace backward push scanning
   with PDB type/callsite information or a small data-flow analysis. COM/vtable
   calls and calls through globals need robust argument and cleanup handling.

5. **External memory havoc is broad.** It is sound but expensive. Compute a
   relevant-memory slice per call without weakening observability.

6. **Project/PDB extraction is repeatedly rebuilt.** Cache PDB type databases,
   inventory, PE parsing, relocated functions, Capstone results, and where safe
   angr projects. Keep worker isolation in mind when choosing cache ownership.

7. **Loops and nontermination are bounded.** A timeout or step limit is
   inconclusive. No induction proof exists in this prototype.

8. **Exceptions, synchronous faults, and atomics are not modeled.** SEH-chain
   access, trap instructions, and lock-prefixed atomics are rejected.

9. **Jump tables need semantic validation.** Table bytes and layout may differ;
   dispatch behavior should be compared. Embedded table bytes can also confuse
   linear disassembly, so executed-code discovery must not rely solely on it.

10. **Proof records are implemented but campaign persistence is TSV-centric.**
    Decide whether per-function `ProofRecord` JSON files or the TSV fingerprint
    are the long-term near-exact ledger format.

11. **Current implementation is a prototype.** The trust argument is weaker
    than the planned Remill/LLVM/Alive2 pipeline. A reliable large campaign is
    needed before deciding whether to harden this route or return to the native
    lifting design.

## Recommended next sequence

1. Run `prototype/test_hardening.py -v` and preserve a clean baseline.
2. Reproduce the live `fx_draw` `Iop_SinF64` escape and fix the semantic hook.
3. Implement candidate-body corpus filtering using the build tree.
4. Run a clean deterministic sample of 20–40 functions with `--jobs 2` while
   the development machine is loaded; inspect every non-success reason.
5. Add a regression for each surfaced bug before changing the campaign model.
6. Improve PDB type-aware alias compatibility, then sample pointer-heavy
   functions specifically.
7. Only after statuses are reliable, regenerate the full 6,889-function corpus
   and run it on the high-memory/high-core machine.
8. Record only fingerprint-valid `EQUIVALENT` results as near exact.

## Notes for a future Remill/Alive2 implementation

If symbolic execution proves too brittle, retain the artifact frontend and
canonical identity work. Lift both sides with Remill, wrap each lifted function
in the PDB-derived source signature, initialize a private Remill state from the
target ABI, inline, run SROA plus the pinned LLVM O3 pipeline and custom memory/
call normalization, then ask Alive2 for refinement in both directions.

Pin Remill, LLVM, Alive2, Z3, and XED as one compatible native-Windows set.
Ghidra control-flow recovery may be reused from Levo. Alive2 loop proofs remain
bounded unless augmented with induction; every result must record unroll bounds.
