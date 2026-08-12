![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

----

Snyk helps you find, fix and monitor for known vulnerabilities in your dependencies, both on an ad hoc basis and as part of your CI (Build) system.

| :information_source: This repository is only a plugin to be used with the Snyk CLI tool. To use this plugin to test and fix vulnerabilities in your project, install the Snyk CLI tool first. Head over to [snyk.io](https://github.com/snyk/snyk) to get started. |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |


## Snyk Docker CLI Plugin

This plugin provides dependency metadata for Docker images.

## Supported functionality

Package managers:

- rpm, apk, deb

Operating systems:

- Debian, Red Hat, Alpine, Oracle, CentOS, SLES, OpenSUSE, Amazon Linux, vanilla Linux
- Distroless and scratch images

Platforms:

- Linux: ARM, AMD, PPC, MIPS, s390x

Image protocols:

- Docker archive, OCI archive
- pulling images from a Docker socket
- pulling from container registries (with support for username and password authentication)

Applications:

- Node (npm, yarn)
- Java (jar files)
- detecting package manager manifests (Python, Ruby)

Others:

- Dockerfile analysis
- identifying Node and Java binaries installed outside the package manager
- running on Windows (_not_ the same as scanning Windows containers)
- collecting the `rootFs` hashes for base image detection and recommendation

## SBOM generation

Pass `--sbom-format=cyclonedx1.5+json` when scanning an image to request a
Software Bill of Materials (SBOM) for the image's dependencies. The only
supported value is `cyclonedx1.5+json`, which produces a CycloneDX 1.5 JSON
document.

When the option is supplied, the scan response includes an `sbom` fact on the
first scan result (the OS dependencies result). The fact's `data` field
contains the CycloneDX document with `bomFormat: "CycloneDX"`,
`specVersion: "1.5"`, and `version: 1`. When the option is omitted, no `sbom`
fact is emitted and scan behavior is unchanged.

## Tests

Refer to [test/README.md](test/README.md) for running and writing tests.
