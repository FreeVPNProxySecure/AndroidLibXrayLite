# AndroidLibXrayLite

AndroidLibXrayLite produces the complete Xray Android native surface consumed
by VPNProtocols: the Go/JNI AAR and the `tun2socks`/HEV tunnel binaries.
The canonical repository and Go module are owned by the `FreeVPNProxySecure`
organization. The historical `github.com/tim06/AndroidLibXrayLite` identity is
retained in provenance as the legacy source path, not as a build dependency.

## Build Contract

The complete native input contract is stored in
[`config/native-build-lock.json`](config/native-build-lock.json). It pins the Go
toolchain, gomobile, Android NDK, Android targets, linker policy, geo assets,
exact tunnel source commits, evidence tools, and GitHub Actions commits.

Required local tools:

- Go `1.25.12`;
- Android NDK `28.2.13676358` (`r28c`);
- JDK 17 or newer for gomobile Android packaging;
- Python 3;
- gomobile at the version declared in the lock.

Validate a checkout:

```bash
python3 scripts/validate_build_contract.py --check-toolchain \
  --ndk-home "$ANDROID_NDK_HOME"
GOTOOLCHAIN=local go mod verify
GOTOOLCHAIN=local go mod tidy -diff
GOTOOLCHAIN=local go test ./...
```

Build to a new output directory:

```bash
scripts/build-android-aar.sh /absolute/path/to/output
```

The build never downloads or refreshes geo assets or tunnel sources and never
mutates `go.mod`, `go.sum`, the NDK, or tracked source. Every tunnel source is
an exact recursive Git submodule pin. Input refresh is a separate reviewed
source change governed by [`docs/RELEASES.md`](docs/RELEASES.md).

gomobile normally creates an absolute filesystem `replace` for a local package,
which is then persisted in Go build info. The build entrypoint instead packages
the exact clean commit as a deterministic local module proxy version and binds
that version. The resulting native payload names the canonical module/version
without embedding the checkout or temporary directory.

`config/android-api-baseline.json` locks the accepted generated manifest,
public Java class signatures, and JNI exports. Every build verifies the
candidate against that contract across all four ABIs before upload.

## Release Model

Pull requests and default-branch pushes run the same contract, test, native
build, rebuild comparison for both output artifacts, artifact, and evidence checks. The build workflow
only creates short-lived Actions artifacts. A separate manual release workflow
accepts an exact successful build run, verifies its source and output manifest,
creates an immutable annotated tag, and publishes the already verified files.

See [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md),
[`docs/RELEASES.md`](docs/RELEASES.md), and [`SECURITY.md`](SECURITY.md).

## License

The repository is licensed under LGPL-3.0; see [`LICENSE`](LICENSE). Native
release bundles also contain a generated dependency license inventory and the
corresponding license texts required by the release contract.
