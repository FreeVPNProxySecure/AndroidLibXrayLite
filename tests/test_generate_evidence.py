from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.generate_evidence import ZIP_TIMESTAMP, archive_license_texts


class LicenseArchiveTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
