# SPDX-License-Identifier: Apache-2.0

"""The Matter gateway (components/esp32_matter_gateway) on the host: its pure-C
parts, the stream protocol chip-tool-gw shares, and its entry points.

Needs cJSON's sources: CJSON_SOURCE_DIR, or an example build's managed
components (examples/gateway/managed_components)."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components/esp32_matter_gateway"
# cJSON's sources: CI checks them out; an example build has them too.
JSON = Path(os.environ.get(
    "CJSON_SOURCE_DIR", ROOT / "examples/gateway/managed_components/espressif__cjson/cJSON"
))


def function_source(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for end in range(brace, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1]
    raise AssertionError(f"Unclosed function: {signature}")


def compiler() -> list[str]:
    cc = shlex.split(os.environ.get("CC", "cc"))
    if not cc or shutil.which(cc[0]) is None:
        raise unittest.SkipTest("C compiler unavailable")
    return cc


def run(cmd: list[str]) -> str:
    done = subprocess.run(cmd, capture_output=True, text=True)
    if done.returncode:
        raise AssertionError(" ".join(cmd[:2]) + "\n" + done.stdout + done.stderr)
    return done.stdout


class MatterGatewayHostTest(unittest.TestCase):
    def test_commands_and_datasets(self):
        cc = compiler()
        with tempfile.TemporaryDirectory() as name:
            out = Path(name)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-DCJSON_NESTING_LIMIT=16",
                     "-I", str(JSON), "-I", str(COMPONENT)]
            run([*cc, *flags, "-c", str(JSON / "cJSON.c"), "-o", str(out / "cjson.o")])
            run([*cc, *flags, str(COMPONENT / "mgw_cmd.c"), str(COMPONENT / "thread_dataset.c"),
                 str(ROOT / "tests/cmd_harness.c"), str(out / "cjson.o"), "-lm",
                 "-o", str(out / "harness")])
            self.assertIn("esp32_matter_gateway: ok", run([str(out / "harness")]))


def cxx_compiler() -> list[str]:
    cxx = shlex.split(os.environ.get("CXX", "c++"))
    if not cxx or shutil.which(cxx[0]) is None:
        raise unittest.SkipTest("C++ compiler unavailable")
    return cxx


class MatterGatewayProtocolTest(unittest.TestCase):
    """The stream protocol the gateway and chip-tool-gw share (core/mgw_proto.cpp)."""

    def test_frames_messages_and_fields(self):
        cxx = cxx_compiler()
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "proto"
            run([*cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(COMPONENT / "core"),
                 str(ROOT / "tests/proto_harness.cpp"), str(COMPONENT / "core/mgw_proto.cpp"),
                 "-o", str(binary)])
            self.assertIn("mgw_proto: ok", run([str(binary)]))

    def test_only_the_alpn_carries_the_version(self):
        # The PSK identity stays the same from one protocol version to the
        # next, so a client of another version fails on the ALPN, not on the
        # secret (mgw_proto.h, "Versions").
        proto = (COMPONENT / "core/mgw_proto.h").read_text()
        alpn = re.search(r'kAlpn\[\]\s*=\s*"([^"]+)"', proto).group(1)
        identity = re.search(r'kIdentityName\[\]\s*=\s*"([^"]+)"', proto).group(1)
        self.assertRegex(alpn, rf"^{re.escape(identity)}/[0-9]+$")
        self.assertNotIn("/", identity)
        keys = (COMPONENT / "core/mgw_keys.cpp").read_text()
        self.assertNotIn("kAlpn", function_source(keys, "bool TlsIdentity("))


class MatterGatewayEntryTest(unittest.TestCase):
    def test_boot_before_setup_forgets_the_fabric(self):
        # A boot before the application's setup erases what a previous owner
        # left, and starts nothing.
        source = (COMPONENT / "esp32_matter_gateway.cpp").read_text()
        init = function_source(source, 'extern "C" void esp32_matter_gateway_init(')
        before = init[init.index("if (!config->setup_complete)"):]
        before = before[:before.index("return;")]
        self.assertIn("erase_if_used();", before)
        self.assertNotIn("mgw_start(", before)


if __name__ == "__main__":
    unittest.main()
