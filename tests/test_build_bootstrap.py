from __future__ import annotations

import inspect
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import build_android_aar
from scripts.validate_build_contract import ContractError, load_lock


ROOT = Path(__file__).resolve().parents[1]
LOCK = load_lock(ROOT)
MOBILE = LOCK["gomobile"]


def build_info(package: str, version: str = MOBILE["version"], module_sum: str = MOBILE["moduleSum"]) -> str:
    return (
        f"/tmp/bin/tool: go{LOCK['go']['version']}\n"
        f"\tpath\t{package}\n"
        f"\tmod\t{MOBILE['module']}\t{version}\t{module_sum}\n"
        "\tdep\tgolang.org/x/mod\tv0.22.0\th1:example=\n"
    )


def locked_go_is_active() -> bool:
    try:
        output = subprocess.run(["go", "version"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return False
    return output.startswith(f"go version go{LOCK['go']['version']} ")


class MobileToolBootstrapTest(unittest.TestCase):
    def test_build_never_runs_gomobile_init(self) -> None:
        # `gomobile init` installs gobind@latest; bind needs only the locked gobind.
        source = inspect.getsource(build_android_aar.build)
        self.assertNotIn('"init"', source)
        self.assertIn("install_gobind(", source)

    def test_gobind_is_installed_from_the_locked_module_version(self) -> None:
        calls = []

        def fake_run(command, *, root, env, capture=False):
            calls.append((command, env.get("GOBIN")))
            return subprocess.CompletedProcess(command, 0, build_info("golang.org/x/mobile/cmd/gobind"), "")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(build_android_aar, "run", fake_run):
            gobind = build_android_aar.install_gobind(LOCK, ROOT, {"PATH": "/usr/bin"}, Path(directory))
        self.assertEqual(Path(directory) / "gobind", gobind)
        self.assertEqual(
            (["go", "install", f"golang.org/x/mobile/cmd/gobind@{MOBILE['version']}"], directory),
            calls[0],
        )
        self.assertEqual(["go", "version", "-m", str(Path(directory) / "gobind")], calls[1][0])
        self.assertNotIn("@latest", " ".join(calls[0][0]))

    def test_tool_identity_requires_package_module_version_and_checksum(self) -> None:
        cases = {
            "latest gobind": build_info(
                "golang.org/x/mobile/cmd/gobind", "v0.0.0-20260908204917-8b95e45f8d3e", "h1:other="
            ),
            "wrong checksum": build_info("golang.org/x/mobile/cmd/gobind", module_sum="h1:other="),
            "gomobile passed as gobind": build_info("golang.org/x/mobile/cmd/gomobile"),
        }
        for label, metadata in cases.items():
            result = subprocess.CompletedProcess([], 0, metadata, "")
            with self.subTest(label), mock.patch.object(build_android_aar, "run", return_value=result):
                with self.assertRaisesRegex(ContractError, "gobind binary does not match"):
                    build_android_aar.require_mobile_tool(Path("/tmp/gobind"), "gobind", LOCK, ROOT, {})
        result = subprocess.CompletedProcess([], 0, build_info("golang.org/x/mobile/cmd/gomobile"), "")
        with mock.patch.object(build_android_aar, "run", return_value=result):
            build_android_aar.require_mobile_tool(Path("/tmp/gomobile"), "gomobile", LOCK, ROOT, {})

    @unittest.skipUnless(locked_go_is_active(), "requires the locked Go toolchain, as in the build workflow")
    def test_locked_gobind_installs_and_verifies_with_the_locked_go(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, "GOFLAGS": "-mod=readonly"}
            gobind = build_android_aar.install_gobind(LOCK, ROOT, env, Path(directory))
            self.assertTrue(gobind.is_file())


if __name__ == "__main__":
    unittest.main()
