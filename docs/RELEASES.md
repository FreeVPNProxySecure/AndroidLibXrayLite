# Native Release Procedure

## Inputs

`config/native-build-lock.json` is the machine-readable source of truth. A pull
request changing any locked input must explain the need, update exact hashes and
source URLs, and pass the full build/evidence workflow.

Geo assets are normal reviewed source inputs. Refresh each file by downloading
one explicitly named upstream release asset, verifying its published checksum,
replacing only the corresponding tracked file, and updating its lock row. Never
download a `latest` release during build or concatenate data/checksum assets.

The baseline AAR built by `v25.8.29-16kb-support-2` accidentally appended the
upstream checksum text to both embedded `.dat` files because one `wget -O`
command consumed multiple URLs. The pinned clean assets in this repository are
the exact data portions intended by that build:

- geoip release `202503010000`, SHA-256
  `83337c712b04d8c16351cf5a5394eae5cb9cfa257fb4773485945dce65dcea76`;
- domain-list-community release `20250829121920`, SHA-256
  `186158b6c2f67ac59e184ed997ebebcef31938be9874eb8a7d5e3854187f4e8d`.

## Candidate Build

1. Merge a reviewed producer pull request after exact-head CI.
2. Run `Native build` for the exact default-branch commit.
3. Require contract/test success, two clean-root builds, artifact comparison,
   compatibility checks, component/license/advisory evidence, and provenance.
4. Download the workflow bundle and independently verify its manifest and
   checksums before release approval.

## Publication

1. Choose a new version tag and the successful candidate build run ID.
2. Run `Native release` with the tag, expected source SHA, and build run ID.
3. The workflow verifies that the SHA is the current default-branch head, the
   build run completed successfully for the same repository/SHA/workflow, and
   every bundled file matches the signed manifest.
4. The workflow creates one annotated tag and uploads the already verified
   bundle. It performs no native build and no source mutation.
5. Existing tags or releases cause a hard failure.

## Consumer Acceptance

VPNProtocols verifies release assets and evidence before replacing either AAR
copy. Static acceptance is followed by a canonical local API 37 emulator Xray
campaign. Producer and consumer waivers are removed only when their exact
replacement evidence is accepted.
