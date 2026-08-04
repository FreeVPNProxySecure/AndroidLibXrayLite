from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import validate_build_contract as contract


ROOT = Path(__file__).resolve().parents[1]


class NativeBuildContractTest(unittest.TestCase):
    def test_repository_contract_is_valid(self) -> None:
        lock = contract.validate(ROOT)
        self.assertEqual("1.25.12", lock["go"]["version"])
        self.assertEqual(4, len(lock["android"]["targets"]))

    def test_rejects_tampered_locked_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract_tree(root)
            with (root / "assets/geoip.dat").open("ab") as target:
                target.write(b"tampered")
            with self.assertRaisesRegex(contract.ContractError, "digest mismatch"):
                contract.validate_source_inputs(root, contract.load_lock(root))

    def test_rejects_floating_action(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_contract_tree(root)
            build = root / ".github/workflows/native-build.yml"
            build.write_text(
                build.read_text(encoding="utf-8").replace(
                    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
                    "actions/checkout@v5",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(contract.ContractError, "action revision drift"):
                contract.validate_workflows(root, contract.load_lock(root))

    def test_rejects_unused_action_lock(self) -> None:
        lock = copy.deepcopy(contract.load_lock(ROOT))
        lock["actions"]["example/unused"] = "a" * 40
        with self.assertRaisesRegex(contract.ContractError, "unused"):
            contract.validate_workflows(ROOT, lock)

    def test_rejects_wrong_ndk_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ndk = Path(directory)
            (ndk / "source.properties").write_text(
                "Pkg.Revision = 27.0.0\nPkg.ReleaseName = r27\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(contract.ContractError, "revision mismatch"):
                contract.validate_ndk(ndk, contract.load_lock(ROOT))

    @staticmethod
    def _copy_contract_tree(root: Path) -> None:
        for relative in (
            "config/native-build-lock.json",
            "go.mod",
            "go.sum",
            "assets/geoip.dat",
            "assets/geosite.dat",
            ".github/workflows/native-build.yml",
            ".github/workflows/native-release.yml",
        ):
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())


if __name__ == "__main__":
    unittest.main()
