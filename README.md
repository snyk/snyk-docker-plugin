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
document. The value is required — a bare `--sbom-format` flag or a boolean
`true` is rejected. When the option is omitted, null, or empty, no SBOM is
generated and scan behavior is unchanged.

The option is validated before the image is read. Unsupported values throw an
error listing the accepted format.

When the option is supplied, the scan response includes an `sbom` fact on the
first scan result (the OS dependencies result). The fact's `data` field
contains the CycloneDX document with `bomFormat: "CycloneDX"`,
`specVersion: "1.5"`, and `version: 1`.

For example, with the Snyk CLI flag:

```
--sbom-format=cyclonedx1.5+json
```

Or programmatically, scanning a `docker-archive` image:

```js
const { scan } = require("snyk-docker-plugin");

const result = await scan({
  path: "docker-archive:./image.tar",
  "sbom-format": "cyclonedx1.5+json",
});

const sbomFact = result.scanResults[0].facts.find(
  (fact) => fact.type === "sbom",
);
```

`sbomFact.data` is the CycloneDX document, with these top-level fields:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    { "type": "library", "name": "...", "version": "...", "bom-ref": "...", "purl": "..." }
  ]
}
```

A scan-produced SBOM does not include `serialNumber` or `metadata.timestamp`.

### Limitations

SBOM components come from `depGraph` facts the scan produces. Included
ecosystems:

- OS packages: deb, apk, rpm
- Node (npm, yarn, pnpm)
- Python: pip and Poetry
- .NET (nuget)
- Go (gomodules)
- PHP (composer)

Not included in the SBOM:

- Java JAR dependencies — these yield a `jarFingerprints` fact only, with no
  dep graph
- Detect-only package manager manifests surfaced as `imageManifestFiles`
- Application dependencies when `--exclude-app-vulns` is set
- Node `node_modules` dependencies when `--exclude-node-modules` is set

Each component has a `bom-ref` of the form `pkgManager:name[@version]`. The
`version` field is omitted when the package has no version. Duplicate
`bom-ref` values across graphs collapse to a single component. The `purl`
field is omitted when the package manager has no purl type mapping — in
practice this applies to pnpm and Go (`gomodules`) components.

## Tests

Refer to [test/README.md](test/README.md) for running and writing tests.
