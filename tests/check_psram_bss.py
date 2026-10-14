# SPDX-License-Identifier: Apache-2.0

"""Checks, in an application's linker map, that the component's static data
went to PSRAM (linker.lf.in): ldgen maps by archive name, so a name that
doesn't match fails silently and the data lands in internal RAM.

Run: python3 tests/check_psram_bss.py build/APP.map"""
from __future__ import annotations

import re
import sys

# An input section's address, size and archive (the section's own name may be
# on the line before).
ENTRY = re.compile(r"0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+\S*/lib(\S*esp32_matter_gateway)\.a\(")
SECTION = re.compile(r"^(\.\S+)")


def main(path: str) -> int:
    section = None
    archive = None
    sizes: dict[str, int] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = SECTION.match(line)
            if m:
                section = m.group(1)
            m = ENTRY.search(line)
            if m and section:
                archive = m.group(2)
                sizes[section] = sizes.get(section, 0) + int(m.group(1), 16)
    if archive is None:
        print(f"{path}: no esp32_matter_gateway archive in the map")
        return 1
    psram, internal = sizes.get(".ext_ram.bss", 0), sizes.get(".dram0.bss", 0)
    print(f"lib{archive}.a: .bss {psram} bytes in PSRAM, {internal} in internal RAM")
    if psram == 0 or internal > psram // 10:
        print("the component's .bss isn't in PSRAM: does linker.lf.in name its archive?")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
