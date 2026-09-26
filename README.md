# Revive

Revive is an experimental semantic-equivalence verifier for reconstructed
32-bit Windows x86 functions. It compares a function from a reference PE/PDB
pair with the corresponding function from candidate COFF object files while
allowing harmless compiler differences such as register allocation, private
stack layout, and instruction selection.

The current implementation is a native-Windows prototype built on angr,
PyVEX, Claripy, and Z3. It is intentionally fail-closed: only `EQUIVALENT` and
byte-identical `EXACT_NOW` results are reusable successes. Timeouts, incomplete
memory models, unsupported instructions, extraction failures, and solver
crashes never count as equivalence.

The longer-term Remill/LLVM/Alive2 design is preserved in
[`PLAN-OLD.md`](PLAN-OLD.md). The prototype was built first to test whether
relational symbolic execution is viable on real functions. See
[`HANDOFF.md`](HANDOFF.md) for its implementation state, experiment history,
known limitations, and next work.

## What is compared

The prototype checks:

- return domains and return values;
- ordered external calls, decorated callee identities, and arguments;
- visible memory before calls and at function return;
- globals by canonical object identity and byte offset;
- pointer aliasing admitted by available PDB information;
- escaped private stack objects by logical allocation identity and offset;
- shared incoming machine and floating-point environment state.

Private stack layout, register selection, callee-saved register preservation,
and stack balance are not independently observable.

## Setup

Revive runs natively on Windows. Python 3.12 was used during development; the
pinned packages also work on Python 3.14.

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The live artifact frontend also imports the reconstruction repository's
`tools/byte_match/artifact_matcher.py` and needs `llvm-pdbutil`, the reference
PE and PDB, a configured reconstruction repository, and its object-file build
tree.

Run the self-contained regression suite:

```powershell
.venv\Scripts\python.exe prototype\test_hardening.py -v
```

## Inspect one function

```powershell
.venv\Scripts\python.exe prototype\live_extract.py `
  --repository C:\path\to\reconstruction `
  --build C:\path\to\reconstruction\build `
  --pdb C:\path\to\reference.pdb `
  --exe C:\path\to\reference.exe `
  --symbol "decorated symbol or inventory selector"
```

`live_equiv.py` and the `live_*.py` sample programs exercise the complete
extraction and proof path for individual functions.

## Run a campaign

First generate the corpus by subtracting all exact ledgers from the function
inventory:

```powershell
.venv\Scripts\python.exe prototype\campaign.py `
  --repository C:\path\to\reconstruction `
  --output campaign split
```

Then classify it:

```powershell
.venv\Scripts\python.exe prototype\campaign.py `
  --repository C:\path\to\reconstruction `
  --output campaign run `
  --build C:\path\to\reconstruction\build `
  --pdb C:\path\to\reference.pdb `
  --exe C:\path\to\reference.exe `
  --jobs 12
```

Each function has a total budget of 60 seconds (`--function-timeout`),
covering extraction and every alias case; a worker is killed 30 seconds after
that (`--worker-timeout`). All logical CPUs are used by default (`--jobs`),
and a worker above `--memory-limit` (8 GiB) is killed. Exhausting a limit is
`INCONCLUSIVE`. `--order random --seed N` samples reproducibly.
Each function runs in a disposable child process so a native Z3 failure is
recorded as `SOLVER_CRASH` without killing the campaign. Results are written
atomically to `campaign/results.tsv`; generated campaign data is intentionally
git-ignored.

## Result statuses

- `EXACT_NOW`: candidate bytes equal the relocated reference bytes.
- `EQUIVALENT`: every modeled input was proved observationally equal.
- `NOT_EQUIVALENT`: a satisfiable observable difference was found.
- `INCONCLUSIVE`: exploration timed out, hit a step limit, failed to return,
  or exhausted resources.
- `MODEL_INCOMPLETE`: execution reached memory or control state not covered by
  the explicit model.
- `UNSUPPORTED`: the function requires a deliberately unsupported semantic or
  ABI feature.
- `EXTRACTION_FAILED`: PE/PDB/COFF extraction or identity resolution failed.
- `SOLVER_CRASH`: the isolated worker terminated without returning a result.

Only `EXACT_NOW` and `EQUIVALENT` are positive classifications.
