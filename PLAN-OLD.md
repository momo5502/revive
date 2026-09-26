# Revive Semantic Equivalence Verifier Plan

## Objective

Revive is a standalone verifier for comparing a function in a reference
Windows executable with the corresponding function in candidate COFF object
files. It should accept compiler-level differences such as register selection,
instruction scheduling, instruction selection, and private stack layout while
checking observable semantic equivalence.

The first supported platform is 32-bit x86 Windows. Architecture, ABI, object
format, and control-flow recovery are kept behind explicit interfaces so more
targets can be added later.

## Trusted components

The initial trusted computing base includes:

- Remill's instruction semantics.
- LLVM and the LLVM optimization pipeline.
- Alive2 and its SMT solver.
- Ghidra's instruction and control-flow analysis when Ghidra output is used.
- Revive's artifact parsing, identity canonicalization, ABI bridge, intrinsic
  lowering, and proof-driver logic.

All dependency revisions must be pinned as one compatible set. In particular,
Remill and Alive2 must build against the same LLVM revision.

## Inputs

Required inputs are:

- Reference PE executable.
- Reference PDB.
- One or more candidate COFF object files.
- A decorated function symbol or an unambiguous local-procedure selector.

A candidate PDB is optional but strongly preferred. It provides stronger type
validation, local-symbol resolution, and diagnostics. The reference PDB defines
the function signature and ABI contract used to compare both implementations.

Every input and generated artifact is identified by a cryptographic hash.

## Equivalence contract

Observable behavior includes:

- The function's return value.
- Reads and writes to externally visible memory.
- The exact ordered sequence of calls.
- Each call's exact decorated callee symbol.
- Each call's argument count, types, order, and values.
- References to the same logical global object at the same byte offset.
- Termination behavior, subject to the bounded-loop limitation below.

The two executions interact with the same abstract external environment. Once
a call's decorated symbol and arguments match, both executions receive the
same possible return value and external memory effects from that call.

The following are not independently observable:

- Register allocation.
- Callee-saved register values.
- Stack balance.
- Private stack layout and dead private stack contents.

A local stack frame is private memory. Its layout is ignored unless a pointer
to part of it escapes through a call, return value, or externally visible
store. Escaped pointers are compared relationally as allocation-plus-offset,
not by incidental concrete stack address.

## Initially deferred behavior

The first implementation does not certify functions whose equivalence depends
on:

- Windows SEH or C++ exception unwinding.
- Precise synchronous hardware-fault behavior.
- Volatile memory accesses.
- Atomic operations or concurrent-memory semantics.
- Floating-point environment state, including x87 control/status and MXCSR.

Detection of one of these conditions produces `UNSUPPORTED`; it must never be
silently approximated as ordinary behavior.

Floating-point computations may be supported when they do not inspect or
modify the floating-point environment and both Remill and Alive2 support the
required operations.

## Artifact and type frontend

Revive extracts and caches a reference inventory from the PDB and PE:

- Procedures, decorated public symbols, local procedures, source/object
  ownership, addresses, and lengths.
- Function signatures, return types, parameter types, calling conventions,
  and relevant qualifiers.
- Data symbols, type indices, storage ranges, structure layouts, arrays,
  unions, enumerations, bitfields, and alignment.
- PE sections, imports, exports, and address-to-symbol mappings.

Candidate COFF processing extracts:

- Sections, COMDATs, symbols, function ranges, and raw bytes.
- Relocations and their addends.
- Compiler-generated constants and local labels.
- CodeView information available in the objects.

Candidate PDB information augments this data when available. All resolution is
fail-closed: missing or ambiguous ownership yields `INCONCLUSIVE` rather than a
guessed identity.

PDB types should be used as fully as defensible for ABI construction, data
layout, object bounds, alignment, and qualified pointer relationships. Revive
must not invent preconditions that the PDB does not establish.

## Canonical identity model

### Functions and calls

A callee is identified by its exact decorated symbol. Different decorated
symbols are different calls even if their implementations appear extensionally
equivalent. Local procedures use a stable identity containing their owning PDB
module and procedure record.

Imports resolve to their actual imported decorated symbol. An alias or thunk is
collapsed only when artifact metadata proves that it represents that same
symbol.

### Globals

Every global reference is canonicalized to:

```text
(root decorated global symbol, byte offset)
```

PDB type layouts and overlapping typed storage ranges are used to map a symbol
that names a structure member or interior subobject back to the containing
global and exact offset. Ambiguous containing objects are not guessed.

### Constants

Compiler-generated immutable constants, including strings and floating-point
constants, are matched by type and contents rather than compiler-generated
symbol spelling or address. Pooling differences are therefore allowed.

Jump tables are not compared as ordinary constants unless their address or
contents escape as data. Their dispatch behavior is normalized as control flow.

## Control-flow recovery

Revive may reuse the Ghidra-based approach demonstrated by Levo. A native
headless workflow exports a deterministic, inspectable function description
containing:

- Function entry and basic blocks.
- Instruction boundaries and bytes.
- Direct successors and direct calls.
- Indirect-control-flow sites.
- Complete indirect-target sets where recoverable.
- Jump-table selector-to-destination mappings.
- Symbolic references relevant to lifting.

The exporter output is cached and hashed. Revive validates it against function
boundaries, decoded instructions, PE data, COFF relocations, and Remill's
decoder. Incomplete indirect control flow produces `INCONCLUSIVE`.

Jump tables are lowered to canonical LLVM branches or `switch` instructions.
Different table addresses, widths, ordering, and layouts are acceptable when
they implement the same dispatch behavior.

## Remill lifting and ABI bridge

Remill lifts every reachable basic block into LLVM IR using 32-bit x86
semantics. No reachable instruction may be omitted or replaced by an assumed
summary without an explicit model.

For each side, Revive creates an ABI wrapper derived from the reference PDB:

```text
typed arguments
  -> x86 entry register/stack state
  -> lifted machine function
  -> typed return value
```

The wrapper creates a private stack object, places arguments according to the
calling convention, establishes a synthetic return continuation, and
initializes all relevant architectural state. Ambient state that may affect
behavior is represented by stable symbolic inputs rather than unconstrained
LLVM `undef` uses.

The same reference signature is used for both implementations. Candidate type
information validates the mapping when available but does not silently change
the comparison contract.

## Memory and call lowering

Remill memory intrinsics are lowered into a shared LLVM memory model:

- Private stack accesses refer to private LLVM allocations.
- Pointer arguments refer to Alive2-visible input memory objects.
- Globals refer to canonical external global declarations.
- Immutable constants refer to canonical content-backed objects.
- Escaped local pointers retain allocation identity and byte offset.

Direct machine calls are converted to conservative, side-effecting LLVM
declarations whose names are the exact decorated symbols. Arguments and return
values are marshalled through the callee's PDB signature when available. An
unresolved or ambiguous call target is inconclusive.

Calls remain conservatively side-effecting so LLVM cannot delete or reorder
them. An extra, missing, reordered, renamed, or differently parameterized call
must be observable to Alive2.

## IR normalization

Each side independently passes through the same pinned pipeline:

1. Validate complete instruction and CFG coverage.
2. Lift Remill basic blocks.
3. Create and inline the typed ABI wrapper.
4. Lower supported Remill memory and control-flow intrinsics.
5. Canonicalize calls, globals, constants, and jump-table control flow.
6. Inline lifted instruction semantics into the wrapper.
7. Run `mem2reg`, SROA, instcombine, CFG simplification, and dead-code cleanup.
8. Run LLVM's pinned default `O3` pipeline.
9. Eliminate dead machine-state fields and private stack artifacts.
10. Verify the resulting LLVM module.

Custom transformations should be small, explicit LLVM passes with focused
tests. Intermediate IR before and after every custom stage can be retained for
diagnostics and reproducibility.

## Alive2 proof

Revive emits target and candidate modules with identical comparison-function
types and invokes Alive2 in both refinement directions:

```text
reference refines candidate
candidate refines reference
```

Both directions must succeed before the function is considered equivalent.
Timeouts, unsupported LLVM constructs, solver errors, or incomplete models are
inconclusive rather than successful.

### Known loop limitation

Alive2 handles loops using bounded unrolling rather than general induction.
Revive accepts an Alive2 success as `EQUIVALENT`, but every result involving a
loop must record the source and target unroll bounds. Documentation and machine
readable output must state that differences requiring more iterations than the
configured bounds may be missed, including differences in nontermination.

Bounded loop checking can later be augmented by relational invariants and
inductive transition proofs without changing the artifact or lifting layers.

## Result model

Revive has five stable outcomes:

- `EQUIVALENT`: both Alive2 refinement directions succeeded.
- `NOT_EQUIVALENT`: Alive2 produced a counterexample or observable mismatch.
- `UNSUPPORTED`: the function requires a deliberately unmodeled feature.
- `INCONCLUSIVE`: analysis, identity resolution, or solving could not decide.
- `ERROR`: invalid inputs or an infrastructure failure prevented verification.

Reports include:

- Input hashes and selected function identity.
- Pinned dependency revisions.
- Recovered signature and calling convention.
- CFG provenance and completeness checks.
- Canonical calls, globals, constants, and unresolved references.
- Normalization pipeline and retained IR artifact paths.
- Alive2 commands, results, counterexamples, and time limits.
- Loop presence, unroll bounds, and the bounded-proof warning.

## Native Windows build

The CMake layout follows the useful structure of Levo without copying its
unrelated translator functionality:

- A top-level project for Revive's native component and tests.
- A separate dependency superbuild.
- A local dependency installation prefix.
- Pinned LLVM, Remill, Alive2, Z3, XED, and supporting libraries.
- Ninja with MSVC or clang-cl as required by the pinned dependency set.
- Native headless Ghidra integration.
- No WSL or Docker requirement.

## Validation

Positive test pairs cover differences in:

- Register allocation.
- Private stack-slot layout.
- Equivalent x86 instruction selection and scheduling.
- Branch layout.
- Constant pooling.
- Switch and jump-table layout.

Negative test pairs deliberately change:

- Return values.
- Memory reads, writes, widths, or offsets.
- Global identity or interior offset.
- Callee symbol, call order, or call arguments.
- Branch conditions.
- Loop-body behavior.
- Constant contents.

Infrastructure tests cover public and local functions, PDB type collisions,
imports, overlapping typed globals, relocations and addends, ambiguous symbols,
incomplete CFGs, unsupported instructions, solver timeouts, and every deferred
semantic category.

Small hand-authored assembly fixtures verify Remill/ABI behavior directly.
Compiler-generated fixture pairs exercise realistic MSVC code generation. Test
artifacts must be redistributable and must not depend on private reference
binaries.
