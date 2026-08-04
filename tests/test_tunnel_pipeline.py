from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.build_tunnel_bundle import verify_tunnel_archive
from scripts.capture_tunnel_advisories import capture
from scripts.validate_build_contract import ContractError, load_lock


ROOT = Path(__file__).resolve().parents[1]


class TunnelPipelineTest(unittest.TestCase):
    def test_archive_rejects_incomplete_native_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "xray-tunnel-binaries.zip"
            with zipfile.ZipFile(artifact, "w"):
                pass
            with self.assertRaisesRegex(ContractError, "entry mismatch"):
                verify_tunnel_archive(artifact, ROOT)

    @patch("scripts.capture_tunnel_advisories.urllib.request.urlopen")
    def test_advisory_capture_covers_every_locked_source(self, urlopen) -> None:
        lock = load_lock(ROOT)
        urlopen.return_value = io.BytesIO(
            json.dumps({"results": [{} for _ in lock["tunnels"]["sources"]]}).encode()
        )

        evidence = capture(ROOT)

        self.assertEqual(0, evidence["findingCount"])
        self.assertEqual(len(lock["tunnels"]["sources"]), len(evidence["records"]))

    @patch("scripts.capture_tunnel_advisories.urllib.request.urlopen")
    def test_advisory_capture_rejects_partial_response(self, urlopen) -> None:
        urlopen.return_value = io.BytesIO(json.dumps({"results": [{}]}).encode())
        with self.assertRaisesRegex(ContractError, "incomplete"):
            capture(ROOT)


if __name__ == "__main__":
    unittest.main()
