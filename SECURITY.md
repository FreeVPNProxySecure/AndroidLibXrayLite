# Security Policy

## Supported Releases

Only the latest release published by the canonical
`FreeVPNProxySecure/AndroidLibXrayLite` repository is eligible for security
support. Historical releases from personal or upstream forks remain traceable
references but are not canonical publication inputs.

## Reporting

Report suspected vulnerabilities through GitHub private vulnerability
reporting for the canonical repository. Do not include credentials, user VPN
configuration, traffic contents, private endpoint details, or other personal
data in a public issue.

## Release Security Boundary

A supported native release must be generated from an exact reviewed
default-branch commit and must include:

- immutable Go, tunnel source, toolchain, module, and geo asset identities;
- independent rebuild comparison for the AAR and tunnel bundle;
- AAR, tunnel ZIP, ABI, ELF, generated API, JNI, 16 KB, and path-leak checks;
- Go and tunnel dependency, license, and advisory evidence;
- artifact checksums and build provenance;
- an immutable annotated tag and GitHub release.

Unknown advisory or license state is not equivalent to clean. A release is
blocked unless the evidence is complete or an explicit bounded disposition is
reviewed in source.
