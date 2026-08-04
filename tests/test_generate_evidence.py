from __future__ import annotations

from pathlib import Path
import copy
import tempfile
import unittest
import zipfile

from scripts.generate_evidence import (
    ZIP_TIMESTAMP,
    archive_license_texts,
    spdx_from_text,
    validate_tunnel_evidence,
)
from scripts.validate_build_contract import ContractError, load_lock


ROOT = Path(__file__).resolve().parents[1]


class LicenseArchiveTest(unittest.TestCase):
    def test_legacy_three_clause_bsd_text_is_detected(self) -> None:
        text = (
            "Redistribution and use in source and binary forms are permitted. "
            "The name of the author may not be used to endorse or promote products."
        )
        self.assertEqual("BSD-3-Clause", spdx_from_text(text))

    def test_license_archive_is_flat_release_asset_and_deterministic(self) -> None:
        payloads: list[bytes] = []
        for index in range(2):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                licenses = output / "licenses"
                licenses.mkdir()
                (licenses / "b-LICENSE").write_text("second\n", encoding="utf-8")
                (licenses / "a-LICENSE").write_text("first\n", encoding="utf-8")

                archive = archive_license_texts(output)

                self.assertFalse(licenses.exists())
                with zipfile.ZipFile(archive) as value:
                    self.assertEqual(
                        ["licenses/a-LICENSE", "licenses/b-LICENSE"], value.namelist()
                    )
                    self.assertTrue(
                        all(info.date_time == ZIP_TIMESTAMP for info in value.infolist())
                    )
                payloads.append(archive.read_bytes())
        self.assertEqual(payloads[0], payloads[1])

    def test_tunnel_evidence_requires_exact_locked_source_identities(self) -> None:
        lock = load_lock(ROOT)
        source_sha = "a" * 40
        manifest = {
            "schemaVersion": 1,
            "contract": "androidlibxraylite-tunnel-manifest-v1",
            "artifact": {"name": lock["tunnels"]["artifactName"]},
            "source": {
                "repository": lock["canonicalRepository"],
                "commitSha": source_sha,
            },
            "upstreamSources": lock["tunnels"]["sources"],
            "toolchain": {
                "androidNdk": lock["android"]["ndk"],
                "minimumApi": lock["tunnels"]["minimumApi"],
                "pageSizeBytes": lock["tunnels"]["pageSizeBytes"],
            },
        }
        advisories = {
            "schemaVersion": 1,
            "contract": "androidlibxraylite-tunnel-advisory-evidence-v1",
            "provider": {
                "name": "OSV",
                "endpoint": "https://api.osv.dev/v1/querybatch",
            },
            "reviewedAt": lock["reviewedAt"],
            "findingCount": 0,
            "records": [
                {
                    "identity": f"git:{source['repository']}@{source['commitSha']}",
                    "query": {"commit": source["commitSha"]},
                    "status": "complete",
                    "advisoryIds": [],
                }
                for source in lock["tunnels"]["sources"]
            ],
        }

        validate_tunnel_evidence(lock, manifest, advisories, source_sha)
        tampered = copy.deepcopy(advisories)
        tampered["records"][0]["identity"] = "git:other/source@" + "b" * 40
        with self.assertRaisesRegex(ContractError, "incomplete or inconsistent"):
            validate_tunnel_evidence(lock, manifest, tampered, source_sha)


if __name__ == "__main__":
    unittest.main()
