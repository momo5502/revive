"""Find small live byte mismatches suitable for semantic-prototype testing."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_extract import load_matcher


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--pdb", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--maximum-size", type=int, default=160)
    parser.add_argument("--minimum-size", type=int, default=1)
    parser.add_argument("--maximum-relocations", type=int)
    parser.add_argument("--count", type=int, default=12)
    args = parser.parse_args()

    repository = args.repository.resolve()
    build = args.build.resolve()
    pdb = args.pdb.resolve()
    exe = args.exe.resolve()
    matcher = load_matcher(repository)
    tool = matcher.locate_pdbutil(None)
    inventory = matcher.load_inventory(build, pdb, tool, False)
    pe = matcher.PEImage(exe)
    publics, public_by_name = matcher.public_maps(inventory, pe)
    context = {
        "inventory": inventory,
        "build": build,
        "pe": pe,
        "publics": publics,
        "public_by_name": public_by_name,
        "target_data_rvas": matcher.load_target_data_rvas(
            repository / matcher.DEFAULT_TARGET_DATA_RVAS
        ),
        "target_function_rvas": matcher.load_target_function_rvas(
            repository / matcher.DEFAULT_TARGET_FUNCTION_RVAS
        ),
        "target_data_owners": matcher.load_target_data_owners(
            build, pdb, tool, inventory, pe, publics, False
        ),
    }

    found = 0
    for selector in matcher.inventory_selectors(inventory, pe):
        try:
            record = matcher.resolve_selector(selector, inventory, pe)
            if not args.minimum_size <= record["size"] <= args.maximum_size:
                continue
            result = matcher.verify_one(selector, context)
        except matcher.MatchError:
            continue
        if result["status"] != "BYTE_MISMATCH":
            continue
        if result["target_size"] != result["candidate_size"]:
            continue
        if (args.maximum_relocations is not None and
                result["candidate_relocations"] > args.maximum_relocations):
            continue
        print(
            f"{selector}\t{result['procedure']}\t{result['target_size']}\t"
            f"diffs={result['ordinary_byte_differences']}\t"
            f"relocs={result['candidate_relocations']}"
        )
        found += 1
        if found >= args.count:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
