"""Safety regressions for setup reuse and worker lifetime changes."""

from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import claripy

from angr_equiv import BASE, CallTarget, _prepared_project, execute, rel32
from artifact_cache import artifact_memoize, file_sha256
from campaign import Paths, WorkItem, WorkResult, _isolated_results
from live_extract import _candidate_procedure_index, external_call_contracts, load_matcher
from pdb_frontend import _module_symbols


def worker_fixture(item):
    # Top-level so Windows spawn can import it in the isolated child.
    if item.selector == "crash":
        os._exit(7)
    if item.selector == "hang":
        time.sleep(15)
    return WorkResult(item.selector, "EXACT_NOW", None, (), (os.getpid(),), 0.0)


class CacheTests(unittest.TestCase):
    def test_cached_matcher_restores_pickle_module_identity(self):
        first, second = SimpleNamespace(), SimpleNamespace()
        with patch.dict(sys.modules, {"artifact_matcher": second}), \
                patch("live_extract._cached_matcher", return_value=first):
            self.assertIs(load_matcher(Path("repository")), first)
            self.assertIs(sys.modules["artifact_matcher"], first)

    def test_file_cache_invalidates_and_is_bounded(self):
        reads = []

        @artifact_memoize(maxsize=1)
        def read(path, refresh=False):
            reads.append(path)
            return path.read_bytes()

        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a", Path(directory) / "b"
            a.write_bytes(b"one")
            b.write_bytes(b"two")
            self.assertEqual(read(a), read(a))
            self.assertEqual(len(reads), 1)
            before = file_sha256(a)
            # Same length, different revision: never key only by size/path.
            old = a.stat()
            a.write_bytes(b"new")
            os.utime(a, ns=(old.st_atime_ns, old.st_mtime_ns + 1_000_000))
            self.assertEqual(read(a), b"new")
            self.assertNotEqual(before, file_sha256(a))
            read(a, refresh=True)
            read(a)
            self.assertEqual(len(reads), 4)
            read(b)
            read(a)
            self.assertEqual(len(reads), 6)

    def test_identity_cache_keeps_objects_distinct(self):
        calls = []

        @artifact_memoize()
        def read(value):
            calls.append(value)
            return object()

        first, second = {}, {}
        self.assertIs(read(first), read(first))
        self.assertIsNot(read(first), read(second))
        self.assertEqual(len(calls), 2)

    def test_candidate_indexes_follow_inventory_not_path(self):
        class Matcher:
            inventory = {"procedures": [{"object": "a", "public_symbols": ["old"]}]}

            def load_inventory(self, *args):
                return self.inventory

        matcher = Matcher()
        pair = {"build": Path("build"), "tool": Path("tool"), "matcher": matcher}
        old = _candidate_procedure_index(pair)
        matcher.inventory = {"procedures": [{"object": "a", "public_symbols": ["new"]}]}
        new = _candidate_procedure_index(pair)
        self.assertIn("old", old["by_public"])
        self.assertNotIn("old", new["by_public"])
        self.assertIn("new", new["by_public"])

    def test_module_symbols_invalidate_when_pdb_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            pdb = Path(directory) / "test.pdb"
            tool = Path(directory) / "tool.exe"
            pdb.write_bytes(b"old")
            tool.write_bytes(b"tool")
            with patch("pdb_frontend.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "old symbols"
                self.assertEqual(_module_symbols(str(tool), str(pdb), 0), "old symbols")
                _module_symbols(str(tool), str(pdb), 0)
                self.assertEqual(run.call_count, 1)
                pdb.write_bytes(b"rebuilt")
                run.return_value.stdout = "new symbols"
                self.assertEqual(_module_symbols(str(tool), str(pdb), 0), "new symbols")
                self.assertEqual(run.call_count, 2)

    def test_leaf_function_does_not_build_call_indexes(self):
        pair = {"address": BASE, "reference": b"\xc3", "candidate": b"\x90\xc3"}
        with patch("live_extract._call_symbol_indexes", side_effect=AssertionError):
            self.assertEqual(external_call_contracts(pair), ((), ()))

    def test_project_reuse_does_not_share_memory_or_arguments(self):
        _prepared_project.cache_clear()
        code = bytes.fromhex("8b442404 a300002000 c3")
        first = execute(code, (claripy.BVV(7, 32),))
        second = execute(code, (claripy.BVV(9, 32),))
        self.assertTrue(first.complete and second.complete)
        self.assertEqual(_prepared_project.cache_info().misses, 1)
        self.assertEqual(_prepared_project.cache_info().hits, 1)
        for execution, expected in ((first, 7), (second, 9)):
            state = execution.states[0]
            self.assertEqual(state.solver.eval(state.regs.eax), expected)
            self.assertEqual(state.solver.eval(state.memory.load(0x200000, 4,
                             endness=state.arch.memory_endness)), expected)

    def test_project_key_includes_call_results_and_contracts(self):
        _prepared_project.cache_clear()
        target = BASE + 0x1000
        code = b"\xe8" + rel32(BASE, target) + b"\xc3"
        a = CallTarget(target, "a", 0, fresh_result=False, havoc_memory=False)
        b = CallTarget(target, "b", 0, fresh_result=False, havoc_memory=False)
        for call, value in ((a, 7), (a, 9), (b, 7), (a, 7)):
            result = execute(code, (), (call,), (claripy.BVV(value, 32),))
            self.assertTrue(result.complete, result.issues)
            state = result.states[0]
            self.assertEqual(state.solver.eval(state.regs.eax), value)
            self.assertEqual(state.globals["calls"][0].name, call.decorated_symbol)
        self.assertEqual(_prepared_project.cache_info().misses, 3)
        self.assertEqual(_prepared_project.cache_info().hits, 1)

    def test_project_key_includes_code_base_and_regions(self):
        _prepared_project.cache_clear()
        # Same memory region, different contents must still get fresh memory.
        code = bytes.fromhex("a100002000 c3")
        for value in (1, 2):
            result = execute(code, (), initial_memory=((0x200000, claripy.BVV(value, 32)),))
            self.assertEqual(result.states[0].solver.eval(result.states[0].regs.eax), value)
        execute(code, (), base=BASE + 0x100)
        execute(b"\x90" + code, ())
        execute(code, (), initial_memory=((0x200000, claripy.BVV(0, 64)),))
        self.assertEqual(_prepared_project.cache_info().misses, 4)
        self.assertEqual(_prepared_project.cache_info().hits, 1)


class WorkerTests(unittest.TestCase):
    @staticmethod
    def items(*selectors):
        paths = Paths("repo", "build", "pdb", "exe")
        return [WorkItem(selector, paths, 10, 100, 10,
                         worker_timeout=0.2 if selector == "hang" else 30)
                for selector in selectors]

    def run_items(self, *selectors, **kwargs):
        return list(_isolated_results(self.items(*selectors), jobs=1,
                                     _classify_function=worker_fixture, **kwargs))

    def test_worker_reuse_and_periodic_recycling(self):
        results = self.run_items("one", "two", "three", tasks_per_worker=2)
        self.assertEqual([result.selector for result in results], ["one", "two", "three"])
        self.assertEqual(results[0].counterexample, results[1].counterexample)
        self.assertNotEqual(results[1].counterexample, results[2].counterexample)

    def test_fresh_worker_mode(self):
        results = self.run_items("one", "two", tasks_per_worker=1)
        self.assertNotEqual(results[0].counterexample, results[1].counterexample)

    def test_crash_only_affects_assigned_task(self):
        results = self.run_items("one", "crash", "three")
        self.assertEqual([item.status for item in results], ["EXACT_NOW", "SOLVER_CRASH", "EXACT_NOW"])
        self.assertIn("WORKER_EXIT_CODE:7", results[1].reasons)
        self.assertNotEqual(results[0].counterexample, results[2].counterexample)

    def test_timeout_only_affects_assigned_task(self):
        results = self.run_items("one", "hang", "three")
        self.assertEqual([item.status for item in results], ["EXACT_NOW", "INCONCLUSIVE", "EXACT_NOW"])
        self.assertIn("WORKER_TIMEOUT:0.2s", results[1].reasons)

    def test_memory_limit_replaces_worker(self):
        first_pid = []

        def memory(pid):
            if not first_pid:
                first_pid.append(pid)
            return 1025 if pid == first_pid[0] else 0

        with patch("campaign._process_memory", side_effect=memory), \
                patch("campaign._available_memory", return_value=1 << 40):
            results = self.run_items("one", "two", memory_limit=1024)
        self.assertEqual(results[0].status, "INCONCLUSIVE")
        self.assertTrue(results[0].reasons[0].startswith("MEMORY_LIMIT:"))
        self.assertEqual(results[1].status, "EXACT_NOW")

    def test_closing_generator_terminates_its_children(self):
        before = {child.pid for child in multiprocessing.active_children()}
        iterator = _isolated_results(self.items("one", "hang"), jobs=1,
                                     _classify_function=worker_fixture)
        try:
            self.assertEqual(next(iterator).status, "EXACT_NOW")
        finally:
            iterator.close()
        self.assertEqual({child.pid for child in multiprocessing.active_children()} - before, set())

    def test_parallel_tasks_are_all_returned(self):
        results = list(_isolated_results(self.items("one", "two", "three", "four"), jobs=2,
                                       _classify_function=worker_fixture))
        self.assertEqual(sorted(result.selector for result in results), ["four", "one", "three", "two"])
        self.assertTrue(all(result.status == "EXACT_NOW" for result in results))


if __name__ == "__main__":
    unittest.main()
