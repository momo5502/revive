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

The self-contained suite had 26 passing tests after these changes.

## Review fixes (2026-09-26, second session)

A code review found several ways the prototype could report `EQUIVALENT` for
different behavior, plus gaps that blocked common function shapes. Each
confirmed defect has a regression test in `ReviewRegressionTests`
(`prototype/test_hardening.py`; 49 tests pass). Fixed:

- **External call effects.** A call may read and write every private stack
  region that has escaped so far (through any argument, register argument, or
  a pointer stored inside escaped memory), not only `pointee_size` bytes at
  typed pointer arguments. Calls clobber ECX/EDX.
- **Escaped stack extents.** Frame locals from both PDBs (`S_BPREL32`, EBP
  frames) become logical allocations matched by name, giving exact extents and
  identities. Other escapes use a conservative extent (pointer to frame end);
  differences there are reported as `MODEL_INCOMPLETE`
  (`ESCAPED_STACK_EXTENT_UNKNOWN`), never as proof.
- **Uncertain observables.** Values whose observability depends on an unknown
  contract (indirect-call ECX/EDX, guessed escape extents, ambiguous parameter
  homes) are compared in a second pass; a possible difference yields
  `MODEL_INCOMPLETE`.
- **Caller frame.** Only the frame, return address and incoming argument slots
  are private; writes above them are external.
- **Alias model.** Pointers may lie inside another pointee or inside a
  referenced global, at PDB layout offsets (fields, bases, array elements) or
  every aligned offset when types are unknown. Fresh allocations moved to
  `0x40000000`. `maximum_cases` was silently ignored and is now enforced.
- **Custom calling conventions.** MSVC gives TU-local functions register
  conventions their procedure type does not describe, and the reference and
  candidate may choose different ones (e.g. reference EDX/ECX, candidate
  ECX/EAX). Entry homes are recovered per side from each PDB's parameter
  records and used for both the function under test and its callees. A
  candidate whose declared parameters differ is `NOT_EQUIVALENT`
  (`CANDIDATE_SIGNATURE_MISMATCH`).
- **x87.** FSIN, FCOS, FSINCOS, FPTAN, FPATAN, F2XM1, FYL2X, FYL2XP1, FSCALE and
  FSQRT are uninterpreted pure operations with functional-consistency
  (Ackermann) constraints, independent of order. FSINCOS was the live
  `fx_draw` `Iop_SinF64` failure (inline asm in `FX_GenSpriteVerts`). FPREM,
  FXAM, FXTRACT, BCD and FPU-environment save/restore are `UNSUPPORTED`.
  `__ftol2_sse` pops ST0 and `__CIsqrt` replaces it. Stale C0-C3 flags are no
  longer compared; TOP is compared modulo 8.
- **`int3`** (`__debugbreak`) is an ordered event followed by continuation.
- **Jump tables.** The function's own bytes are readable; region discovery no
  longer overwrites in-function tables with symbolic data.
- **Frontend.** Simple float/double detection no longer matches record type
  indices ending in 0x40/0x41. PDB-absent callees are only given an ABI when C
  decoration or every call site fixes it. Literal lookup is limited to whole
  strings in read-only sections. TLS constants moved out of the synthetic
  constant range. Internal-call detection uses each side's own length. An
  equivalence that rests on a data identity copied from the reference
  (`reference_address_hint`) is `MODEL_INCOMPLETE` (`BORROWED_DATA_IDENTITY`).
- **Campaign.** One driver handles every function. Verifier exceptions are
  `INCONCLUSIVE` (`VERIFIER_ERROR`, `SOLVER_LIMIT`), not `EXTRACTION_FAILED`.
  `--worker-timeout` (default 7200 s) kills a stuck worker. Fingerprints cover
  `campaign.py`, the matcher, the reviewed RVA maps and the target EXE/PDB.
  Implicitly locked `xchg [mem]` is rejected as atomic.

`unicorn==2.1.4` is now pinned so angr's native library loads; the
`UNICORN` state option is not enabled. Before enabling it, confirm that the
`mem_read`/`mem_write` inspection breakpoints still fire for code it runs.

- **Lazy global memory.** Mutable globals are no longer declared. A named
  global resolves to the same address on both sides, so each touched byte is
  a symbol named by address and call epoch (`lazy_<addr>_<epoch>`), shared by
  both executions. Written bytes are compared at every call and at exit; an
  external call starts a new epoch. Only constants with known contents are
  declared. Declaring whole objects (the 1 MB `cgArray`) exhausted memory.
- **Deterministic pointer handling.** angr's fallback concretization picked an
  arbitrary solver model for an unbounded symbolic address and constrained the
  path to it, so verdicts changed between runs. Such accesses now report
  `MODEL_INCOMPLETE` (`UNMODELED_POINTER_ACCESS`).
- **Performance.** Parsed PDB type databases are pickled under `.cache/`
  (keyed by PDB path, size and mtime); candidate procedures are indexed once
  with plain path normalization. Setup fell from about 81 s to about 6 s per
  function. Stack-pointer classification uses a structural check before Z3,
  and access checks reuse one solver per path; the one proved sample function
  went from 179 s to 11 s. Access logs are linked lists. The alias driver
  stops at the first `INCONCLUSIVE` case.
- **Campaign.** Uses every logical CPU by default. `--memory-limit` (8 GiB)
  kills a worker above it (`MEMORY_LIMIT`) and delays new workers until that
  much memory is free. `--function-timeout` (default 60 s) is one budget for
  all alias cases; `--worker-timeout` defaults to that plus 120 s.
  `--order random --seed N` samples reproducibly.

- **Pointer following.** A pointer the function loads from memory or gets
  from a callee is discovered when an access through it is rejected. Its
  source (a slot at a fixed address, a slot inside another entity's pointee,
  or a call return, each per call epoch) becomes an alias-model entity typed
  from the PDB when possible, and enumeration restarts, up to 6 derived
  pointers (`POINTER_DEPTH_LIMIT`). Pointee contents are lazily modeled
  memory, so nested pointers are followed the same way.
- **Second review (five unsound EQUIVALENT paths), each with a test.**
  Ambiguous parameter locations now receive independent values, and a
  difference under an ambiguous ABI is `MODEL_INCOMPLETE`. A stack address
  stored to external memory escapes. Borrowed data identities block the
  `EXACT_NOW` path too. Untyped pointees may partially overlap (straddling
  placements); typed ones follow the C++ object model. Out-of-range FPTAN
  pushes nothing.

- **Third review (three unsound EQUIVALENT paths), each with a test.**
  Fresh objects now have symbolic base addresses (non-null, no wrap, no
  overlap with each other, referenced globals, the stack or code); memory
  accesses through them are mapped to canonical storage in the memory
  breakpoints, adding no path constraint, so address bits stay symbolic and
  allocation-order cases are no longer needed. Accesses past an object's
  modeled extent widen it (dropping its PDB type) and restart the
  enumeration; an arena access no object can own is `MODEL_INCOMPLETE`
  (`POINTEE_ACCESS_OUT_OF_RANGE`, `POINTEE_EXTENT_LIMIT`). Stores of any width
  are scanned for private stack addresses.
- **Budget.** `--function-timeout` (60 s) now covers extraction and all alias
  cases, and final solver queries get the remaining time (`SOLVER_TIMEOUT`);
  workers are killed 30 s after the budget.

Sample, 20 random inexact functions (seed 1246938500), 12 workers, 60 s total
per function, 2.4 minutes wall clock: 1 `EQUIVALENT`, 4 `NOT_EQUIVALENT`
(signature mismatches, assert `__FILE__`/`__LINE__` arguments, a raw instead
of normalized `bool` return; checked against the disassembly), 5
`MODEL_INCOMPLETE` (derived-pointer limit, out-of-range pointee accesses,
no returning state), 9 `INCONCLUSIVE` (budget: loops, recursion, large
functions, one 60 s solver timeout), 1 `UNSUPPORTED`. `CG_GetShellShockBlendTime`
proves `EQUIVALENT` in about 62 s with a larger budget. Open engine errors:
an IR decode error in an `fx_marks` function and a "no bytes in memory" jump
in `CL_GetLocalClientMigrationString`.

## Known issues and open work

### Fourth review fixes and performance (2026-09-26)

The changes following `2234a49` fix four reproduced failures:

- Memory addresses are rebased as `canonical + (actual_address - symbolic_base)`.
  The offset retains dependence on the real base, including alignment masks;
  replacing the base inside the whole expression was unsound.
- Every translated access retains its originating allocation. Its offset must
  fit that allocation's canonical storage window, even if an out-of-range
  access would happen to land in another allocation's slot. Unsupported offsets
  return `MODEL_INCOMPLETE` with `POINTEE_ACCESS_OUT_OF_RANGE` detail.
- External-call havoc uses the same address translation as ordinary writes.
  Previously it bypassed translation and rejected modeled pointer arguments as
  unbounded addresses.
- Publication tracking checks completed four-byte words in memory after stores,
  including words assembled across byte/word stores or spanning store edges.
  It now catches bytewise copies of stack addresses as well as scalar/vector
  stores. These regions participate in subsequent external-call effects.

The regression suite now has 70 passing tests. Tests include positive and
negative pointer-call cases, alignment-dependent accesses, cross-slot accesses,
bytewise stack-pointer publication, and changed branch layouts with a negative
control for path pruning. The cross-slot fixture deliberately remains
`MODEL_INCOMPLETE`; it is not accepted as equivalent.

Profiling `CG_GetShellShockBlendTime` identified the final SMT comparison as
the main bottleneck. The comparison used to include output expressions from
every pair of terminal paths, including mutually exclusive pairs. It now
checks overlap first, using direct contradictory conditions or an UNSAT solver
result to discard impossible pairs. It also caches each state's lazy-memory
snapshot and omits trivially false difference expressions. Coverage checks and
all feasible path comparisons remain required. Solver timeouts stay inconclusive.

Local measurements, using the same artifacts and existing PDB disk caches:

| Version/run | Result | Function elapsed |
| --- | --- | --- |
| `2234a49`, no profiler, 90-second budget | `INCONCLUSIVE / SOLVER_TIMEOUT` | 90.69 s |
| Updated, fresh worker 1, default 60-second budget | `EQUIVALENT` | 14.33 s |
| Updated, fresh worker 2 | `EQUIVALENT` | 14.50 s |
| Updated, fresh worker 3 | `EQUIVALENT` | 14.05 s |

The updated median is 14.33 seconds. Worker startup makes total wall time
larger than the per-function elapsed times. Profiles attributed about 64.1
seconds to Z3 checks before the change and 2.9 seconds afterward. The initial
profile also included cold PDB cache creation, so its extraction timings are
not directly comparable. These are measurements of one representative function,
not a throughput estimate for the full corpus; loop/path explosion and alias
enumeration remain significant costs.

`prototype/benchmark.py` reproduces live timing measurements in fresh isolated
workers, with worker timeout/memory limits, and prints JSON without writing
campaign results. Repeatable command examples are in the root README.

### Setup and worker reuse (2026-09-26)

The one-function path-pruning improvement above was not representative of
campaign throughput. Follow-up profiles found repeated artifact parsing,
process startup, execution setup, and full garbage collections to be material
costs even in small functions. The vector-copy sample performed 90 executions
across its alias cases; this change retains all those cases.

Implemented:

- Campaign workers handle one assigned function at a time, reuse setup for up
  to 32 functions, then recycle (`--tasks-per-worker 1` restores fresh workers).
  Deadlines reset on assignment. Native crashes, hard timeouts and memory-limit
  kills affect only the assigned task; replacements handle remaining work.
  Non-cached `INCONCLUSIVE` results also retire their worker. Closing the result
  generator terminates its children. Windows broken pipes can raise during
  `poll()` as well as `recv()`; both paths are handled.
- `artifact_cache.py` provides bounded read-through metadata and file-hash
  caches. Inventories, globals, PE images, COFF objects, public maps, and data
  owners are reused. Candidate procedure indexes follow inventory identity,
  rather than only a PDB pathname. PDB symbol/type caches also invalidate on
  input changes. The old path-only COFF/Ninja caches are unwrapped and replaced
  with file-revision-aware caches. Type-database disk cache keys now include
  PDB, tool and parser identity (existing old-format entries are not reused).
- Leaf functions skip building call-symbol indexes; other functions reuse
  indexes for the same inventory/image.
- Eight prepared angr projects are cached per process, keyed by code bytes,
  base, complete call contracts/results, and declared memory regions. They
  retain lifted blocks and hook setup. Every execution still creates a fresh
  state, memory, solver constraints, pointer model and inspection callbacks.
  Unsupported-instruction scans are cached separately by bytes/base.
- Explicit GC every eight alias cases now scans the youngest generation;
  every 128 cases still requests a full collection. Automatic GC and worker
  memory limits remain active.

No alias cases or proof obligations were removed. Verdict-cache lookup still
follows extraction/fingerprinting; sharing symbolic execution summaries across
different alias cases and avoiding discovery restarts remain future work.
The implementation fingerprint includes the new cache module, invalidating
old conclusions automatically. No campaign was started, and existing result
files were left untouched.

Cache assumptions: artifacts are immutable during each classification, and
verifier code is immutable during a campaign. Lookups check normalized path,
device/file identity, size, mtime_ns and ctime_ns; a normal rebuild/replacement
invalidates entries. This does not provide a transactional snapshot of a live
build or detect edits that deliberately preserve all tracked metadata. Cached
parsed objects are read-only to consumers. Use fresh workers when diagnosing
cache behavior.

Validation: 86 tests pass with
`.venv\Scripts\python.exe -m unittest discover -s prototype -p 'test_*.py' -q`.
The 16 new tests cover bounded/file-invalidating caches, PDB/index invalidation,
matcher module identity, fresh execution state with reused projects, complete
project keys, worker reuse/recycling, crashes, hard timeouts, memory kills,
parallel delivery, and cancellation cleanup.

Measurements on the same live artifacts, single-worker sequential execution,
60-second function budgets, two passes through three selectors, with PDB disk
caches already populated:

| Configuration | Six-task wall time (includes child startup) |
| --- | ---: |
| `e6586e5`, original fresh workers | 71.92 s |
| Updated code, `--tasks-per-worker 1` | 59.16 s |
| Updated code, `--tasks-per-worker 32` | 40.20 s |

| Selector | Original median | Updated fresh median | Updated reuse median |
| --- | ---: | ---: | ---: |
| `?IWNet_HandleSessionUpdateFailure@@YA_NPAUIWNetCommandData@@PAUmsg_t@@@Z` | 3.93 s | 2.63 s | 2.03 s |
| `@physics/ode/src/ode.cpp:0x2dbd00:0x1c58` | 10.56 s | 7.96 s | 6.90 s |
| `?CG_GetShellShockBlendTime@@YAHH@Z` | 11.97 s | 10.09 s | 9.48 s |

Every measurement was a fresh proof (`cached=false`), and every verdict was
`EQUIVALENT`. The two updated configurations produced identical fingerprints
per selector. Individual times exclude process startup; reuse medians mix
worker-cold and worker-warm tasks. Reproduce with `prototype/benchmark.py`, the
three repeated `--symbol` options above, `--repeat 2`, and
`--tasks-per-worker 1` or `32`. Updated reuse reduced measured wall time by
44% (about 1.79x throughput) for this sample, not a corpus-wide guarantee.
Hard loop/solver-bound functions can still exhaust their unchanged budget.

### Remaining limitations

1. **Pointer following limits.** Derived pointers are capped at 6 per
   function; pointers computed arithmetically from other loaded values are
   not derivable and stay `UNMODELED_POINTER_ACCESS`. Untyped discovered
   pointees are assumed 64 bytes. Lazy allocation of such
   pointees with their own alias cases is the largest remaining coverage gap.
2. **Typed overlaps.** With PDB types, placements follow the C++ object
   model (no partial overlap of distinct complete objects), not punning.
3. **Large-array placements.** A pointer that may point into a large global
   array yields one case per element and can hit the case limit.
4. **Indirect calls** still infer stack arguments from nearby pushes and do
   not model x87/EDX:EAX returns.
5. **Recursion** runs the body again instead of treating the self-call as an
   ordered event, so recursive functions time out.
6. **Struct returns** through a hidden pointer are not modeled.
7. **x87 precision.** VEX evaluates x87 in 64-bit double precision and ignores
   precision control; extended-precision intermediates are not modeled.
8. **Parameter homes** rely on VC8 emitting parameter records first and in
   order, and assume a standard prologue for candidate callees.
9. **Candidate-less corpus filtering** is still not implemented in `split`.
10. **Budget-bound functions.** Most non-proofs exhaust the 60 s budget in
    exploration (loops, recursion, large functions).
11. **Performance.** Escape havoc and snapshots are per 4-byte chunk; bounded
    tables above 1024 entries are rejected as unmodeled.
12. **Loops/nontermination** remain bounded; SEH, faults and atomics are not
    modeled.
13. **Proof-record format** (TSV fingerprint vs per-function JSON) is undecided.

## Recommended next sequence

1. Run `prototype/test_hardening.py -v`.
2. Investigate the open engine errors from the latest sample.
3. Implement lazy pointee allocation (item 1), then sample pointer-heavy
   functions.
4. Only after statuses are reliable, run the full corpus on the large machine.
5. Record only fingerprint-valid `EQUIVALENT` results as near exact.

## Notes for a future Remill/Alive2 implementation

If symbolic execution proves too brittle, retain the artifact frontend and
canonical identity work. Lift both sides with Remill, wrap each lifted function
in the PDB-derived source signature, initialize a private Remill state from the
target ABI, inline, run SROA plus the pinned LLVM O3 pipeline and custom memory/
call normalization, then ask Alive2 for refinement in both directions.

Pin Remill, LLVM, Alive2, Z3, and XED as one compatible native-Windows set.
Ghidra control-flow recovery may be reused from Levo. Alive2 loop proofs remain
bounded unless augmented with induction; every result must record unroll bounds.
