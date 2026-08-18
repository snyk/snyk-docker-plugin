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

## SBOM output

When the `sbom` option is truthy (the Snyk CLI's `--sbom` flag), the plugin
additionally emits a `sbom` fact on the first scan result: a CycloneDX 1.6
JSON document (`bomFormat`, `specVersion`, `serialNumber`, `metadata`,
`components`) describing everything found in the scan target, alongside the
plugin's regular dependency-graph output. Nothing changes when the option is
absent or falsy.

The document can be assembled from up to three input shapes, and any
combination of them is folded into a single BOM:

- the image's OS packages (from the dependency tree built while scanning an
  image or archive)
- application dependencies (npm, Java, Python, etc., when application
  scanning is enabled)
- Dockerfile analysis (the base image and any packages installed by `RUN`
  instructions), when a Dockerfile is supplied

A package discovered through more than one of these (for example, both
installed in the image and named in a Dockerfile `RUN` instruction) appears
as a single component rather than being duplicated.

Two known limits to the enumeration:

- packages detected only through Dockerfile analysis have no version
  information, since that is not something static Dockerfile parsing can
  recover
- jars identified only by content fingerprint, with no resolved Maven
  coordinates, cannot be named as components and are not listed

## Tests

Refer to [test/README.md](test/README.md) for running and writing tests.
