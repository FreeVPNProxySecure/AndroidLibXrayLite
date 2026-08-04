# Ownership And Trust Boundary

## Canonical Repository

`FreeVPNProxySecure/AndroidLibXrayLite` is the canonical producer. It owns:

- native Go source and the checked-in geo inputs;
- Go, gomobile, Android NDK, target, linker, and Actions locks;
- deterministic tests, build scripts, and rebuild comparison;
- native dependency, license, advisory, compatibility, and provenance evidence;
- annotated tags and immutable native release assets.

`tim06/AndroidLibXrayLite` is the historical upstream reference for the current
fork ancestry. `2dust/AndroidLibXrayLite` is the original source fork. Neither is
an authorized publication location for VPNProtocols after migration.

The canonical Go module path is
`github.com/FreeVPNProxySecure/AndroidLibXrayLite`. The historical
`github.com/tim06/AndroidLibXrayLite` path remains provenance, not an input.
This migration is required because gomobile persists a local module replacement
path in Go build info even with `-trimpath`. Building the exact commit as a
canonical version through a deterministic local module proxy removes the host
path without rewriting native binaries. Generated Java/JNI API comparison is a
mandatory release gate for this identity change.

The reviewed surface is machine-locked in
`config/android-api-baseline.json`; updating it is an API review, not a routine
build refresh.

## Consumer Boundary

`FreeVPNProxySecure/VPNProtocols` owns acceptance of a released AAR: artifact
digest, protocol capability policy, Gradle verification, SDK release evidence,
and connected Android runtime parity. It consumes producer evidence by immutable
release URL and digest. It does not recreate claims that only this producer can
prove.

## Change Authority

- All production changes use pull requests and exact-head CI.
- A producer release is made only from the reviewed default-branch head.
- Build jobs cannot create tags or releases.
- Release jobs cannot compile or alter the AAR.
- Existing tags and release assets are never replaced.
- Toolchain, module, asset, policy, or evidence changes require source review.
- A compromised or incorrect release is superseded by a new version; it is not
  silently mutated.

## Historical Evidence Gap

The Actions logs for `v25.8.29-16kb-support-2` are no longer available (GitHub
returns HTTP 410). The old Go patch version, exact NDK package, and complete
environment are therefore unknown. New releases replace that gap with explicit
evidence; they do not claim to reconstruct unavailable provenance.
