from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.source_module_proxy import (
    create_source_module_proxy,
    escape_module_path,
    source_version,
)


class SourceModuleProxyTest(unittest.TestCase):
    def test_escapes_uppercase_module_path(self) -> None:
        self.assertEqual(
            "github.com/!free!v!p!n!proxy!secure/!android!lib!xray!lite",
            escape_module_path("github.com/FreeVPNProxySecure/AndroidLibXrayLite"),
        )

    def test_source_version_is_bound_to_epoch_and_commit(self) -> None:
        self.assertEqual(
            "v0.0.0-20250831171159-54e6c2599739",
            source_version("54e6c2599739b2bc627aa53fd3bc48cd4a43ba58", 1756660319),
        )

    def test_go_can_download_generated_proxy_version(self) -> None:
        module_path = "example.com/CanonicalModule"
        source_sha = "54e6c2599739b2bc627aa53fd3bc48cd4a43ba58"
        source_epoch = 1756660319
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "go.mod").write_text(
                f"module {module_path}\n\ngo 1.25.0\n", encoding="utf-8"
            )
            (source / "module.go").write_text(
                "package canonicalmodule\n\nconst Ready = true\n", encoding="utf-8"
            )
            subprocess.run(["git", "init", "-q"], cwd=source, check=True)
            subprocess.run(["git", "add", "go.mod", "module.go"], cwd=source, check=True)

            proxy = create_source_module_proxy(
                source, root / "proxy", module_path, source_sha, source_epoch
            )
            driver = root / "driver"
            driver.mkdir()
            (driver / "go.mod").write_text(
                "module example.com/driver\n\n"
                "go 1.25.0\n\n"
                f"require {module_path} {proxy['version']}\n",
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                "GOMODCACHE": str(root / "module-cache"),
                "GOCACHE": str(root / "build-cache"),
                "GOPROXY": f"file://{proxy['proxyRoot']}",
                "GOSUMDB": "off",
            }
            result = subprocess.run(
                ["go", "mod", "download", "-json", f"{module_path}@{proxy['version']}"],
                cwd=driver,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            metadata = json.loads(result.stdout)
            self.assertEqual(module_path, metadata["Path"])
            self.assertEqual(proxy["version"], metadata["Version"])
            self.assertTrue(Path(metadata["Zip"]).is_file())


if __name__ == "__main__":
    unittest.main()
