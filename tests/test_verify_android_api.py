from __future__ import annotations

from pathlib import Path
import unittest

from scripts.validate_build_contract import ContractError
from scripts.verify_android_api import load_baseline, verify_manifest


ROOT = Path(__file__).resolve().parents[1]


class AndroidApiContractTest(unittest.TestCase):
    def test_baseline_is_complete(self) -> None:
        baseline = load_baseline(ROOT)
        self.assertEqual(17, len(baseline["publicClassSignatures"]))
        self.assertEqual(35, len(baseline["jniExports"]))

    def test_manifest_rejects_added_surface(self) -> None:
        baseline = load_baseline(ROOT)
        payload = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="go.libv2ray.gojni"><uses-sdk android:minSdkVersion="21"/><uses-permission android:name="android.permission.INTERNET"/></manifest>"""
        with self.assertRaisesRegex(ContractError, "surface drift"):
            verify_manifest(payload, baseline)


if __name__ == "__main__":
    unittest.main()
