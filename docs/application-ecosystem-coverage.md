# Application ecosystem coverage

This document records which application-level package ecosystems `snyk-docker-plugin` detects inside container images during scanning, based on inspection of the plugin source code (not product documentation or memory).

## Method

Ground truth for “does the plugin detect ecosystem X?” is the extract-action list assembled in [`lib/analyzer/static-analyzer.ts`](../lib/analyzer/static-analyzer.ts) (action list at lines 108–165, consumers invoked at lines 300–385). Every detected application ecosystem is represented by:

1. An **ExtractAction** in `lib/inputs/<ecosystem>/static.ts` (or [`lib/go-parser/index.ts`](../lib/go-parser/index.ts) for Go) whose `filePathMatches` enumerates what it recognises on the image filesystem.
2. An **analyzer** under `lib/analyzer/applications/` (or `lib/go-parser/`) that turns extracted content into a `depGraph` or `jarFingerprints` fact with an `identity.type`.

[`lib/analyzer/applications/index.ts`](../lib/analyzer/applications/index.ts) is **not** the full registry. It re-exports only dotnet, node, php, pip, and poetry. **Java** (`jarFilesToScannedResults`, imported at [`static-analyzer.ts:70`](../lib/analyzer/static-analyzer.ts)) and **Go** (`goModulesToScannedProjects`, imported at [`static-analyzer.ts:6–8`](../lib/analyzer/static-analyzer.ts)) are wired in directly from their own modules. Enumerate detected ecosystems from `static-analyzer.ts`, not from `applications/index.ts`.

Application-ecosystem extraction and analysis are gated on `exclude-app-vulns` being unset/false ([`static-analyzer.ts:134`, `:139`](../lib/analyzer/static-analyzer.ts)); the rows below assume that gate is open.

## Detected

| Ecosystem | Support status | Files / signatures matched | Extract action | Consumer & `identity.type` | Native or delegated |
| --- | --- | --- | --- | --- | --- |
| **Node** (npm, Yarn, pnpm) | Supported | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` ([`lib/inputs/node/static.ts:5–10`](../lib/inputs/node/static.ts)) | [`lib/inputs/node/static.ts`](../lib/inputs/node/static.ts), action `node-app-files` | [`lib/analyzer/applications/node.ts`](../lib/analyzer/applications/node.ts); `identity.type` = `depGraph.pkgManager.name` ([`:245`](../lib/analyzer/applications/node.ts)) | **Delegated** — [`snyk-nodejs-lockfile-parser`](https://www.npmjs.com/package/snyk-nodejs-lockfile-parser) (`package.json:52`) for lockfile/manifest parsing; [`snyk-resolve-deps`](https://www.npmjs.com/package/snyk-resolve-deps) (`package.json:54`) when resolving `node_modules` (gated separately on `exclude-node-modules` at [`static-analyzer.ts:135`, `:305–309`](../lib/analyzer/static-analyzer.ts)) |
| **PHP / Composer** | Supported | `composer.json`, `composer.lock` ([`lib/inputs/php/static.ts:6`](../lib/inputs/php/static.ts)) | [`lib/inputs/php/static.ts`](../lib/inputs/php/static.ts), action `php-app-files` | [`lib/analyzer/applications/php.ts`](../lib/analyzer/applications/php.ts); `identity.type` = `depGraph.pkgManager.name` ([`:65`](../lib/analyzer/applications/php.ts)) | **Delegated** — [`@snyk/composer-lockfile-parser`](https://www.npmjs.com/package/@snyk/composer-lockfile-parser) (`package.json:33`) |
| **Python — Poetry** | Supported | `pyproject.toml`, `poetry.lock` ([`lib/inputs/python/static.ts:6`](../lib/inputs/python/static.ts)) | [`lib/inputs/python/static.ts`](../lib/inputs/python/static.ts), action `poetry-app-files` | [`lib/analyzer/applications/python/poetry.ts`](../lib/analyzer/applications/python/poetry.ts); `identity.type` = `depGraph.pkgManager.name` ([`:42`](../lib/analyzer/applications/python/poetry.ts)) | **Delegated** — [`snyk-poetry-lockfile-parser`](https://www.npmjs.com/package/snyk-poetry-lockfile-parser) (`package.json:53`) |
| **Python — pip** | Supported | `requirements.txt`; installed-package `METADATA` under `lib/python*/site-packages/` or `dist-packages/` matching [`lib/inputs/python/static.ts:9–10`](../lib/inputs/python/static.ts) | [`lib/inputs/python/static.ts`](../lib/inputs/python/static.ts), action `pip-app-files` | [`lib/analyzer/applications/python/pip.ts`](../lib/analyzer/applications/python/pip.ts); literal `identity.type` `'pip'` ([`:172`](../lib/analyzer/applications/python/pip.ts)) | **Native** — in-repo [`lib/python-parser/metadata-parser`](../lib/python-parser/metadata-parser) and [`lib/python-parser/requirements-parser`](../lib/python-parser/requirements-parser) ([`pip.ts:8–10`](../lib/analyzer/applications/python/pip.ts)) |
| **.NET / NuGet** | Partially supported | `*.deps.json` only, excluding paths containing `/dotnet/shared/` or `/dotnet/packs/` ([`lib/inputs/dotnet/static.ts:9–18`](../lib/inputs/dotnet/static.ts)) | [`lib/inputs/dotnet/static.ts`](../lib/inputs/dotnet/static.ts), action `dotnet-app-files` | [`lib/analyzer/applications/dotnet.ts`](../lib/analyzer/applications/dotnet.ts); literal `identity.type` `'nuget'` ([`:115`](../lib/analyzer/applications/dotnet.ts)) | **Native** — parsed in-repo from publish output `.deps.json` |
| **Java / Maven** | Partially supported | `.jar` and `.war` on the image filesystem ([`lib/inputs/java/static.ts:7`](../lib/inputs/java/static.ts)); `/usr/lib` and `gradle/cache` paths ignored at [`static.ts:6`](../lib/inputs/java/static.ts) (re-added for system JARs via `getUsrLibJarFileContentAction` when `include-system-jars` is set) | [`lib/inputs/java/static.ts`](../lib/inputs/java/static.ts), action `jar` | [`lib/analyzer/applications/java.ts`](../lib/analyzer/applications/java.ts); `identity.type` `'maven'` ([`:62`](../lib/analyzer/applications/java.ts)); emits `jarFingerprints` facts, not a dep graph | **Native** — in-repo [`adm-zip`](https://www.npmjs.com/package/adm-zip) archive traversal and `pom.properties` parsing ([`:135–154`](../lib/analyzer/applications/java.ts), [`getCoordsFromPomProperties` `:269–285`](../lib/analyzer/applications/java.ts), [`parsePomProperties` `:292–303`](../lib/analyzer/applications/java.ts)); SHA-1 fingerprint fallback when coordinates are absent ([`:227–236`](../lib/analyzer/applications/java.ts)). **Gap:** no `pom.xml` or `build.gradle` filesystem matcher anywhere in `lib/`; Maven coordinates are read only from `pom.properties` entries inside unpacked archives, never from build files on the image filesystem |
| **Go modules** | Partially supported | Extension-less files outside a fixed ignore list ([`lib/go-parser/index.ts:38–50`](../lib/go-parser/index.ts)); callback `findGoBinaries` keeps only ELF binaries carrying `.go.buildinfo` or `.note.go.buildid` sections ([`:66–107`](../lib/go-parser/index.ts)); module data from embedded build info ([`lib/go-parser/go-binary.ts`](../lib/go-parser/go-binary.ts)) | [`lib/go-parser/index.ts`](../lib/go-parser/index.ts), action `gomodules` ([`:52–56`](../lib/go-parser/index.ts)) | [`goModulesToScannedProjects`](../lib/go-parser/index.ts); literal `identity.type` `'gomodules'` ([`:36`, `:205`](../lib/go-parser/index.ts)) | **Native** — in-repo ELF reader and Go build-info parser. **Gap:** no `go.mod` or `go.sum` filesystem matcher |

### Partial-support gaps (summary)

| Ecosystem | What is detected | What is missing |
| --- | --- | --- |
| .NET / NuGet | Published `*.deps.json` (excluding shared runtime/pack paths) | No matcher for `.csproj`, `packages.config`, `paket.lock`, or `packages.lock.json` |
| Java / Maven | `.jar`/`.war` archives; Maven coordinates from `pom.properties` inside unpacked archives; SHA-1 fallback for Maven Central lookup | No `pom.xml` or `build.gradle` matcher; no Gradle lockfile support; coordinates never read from build files on the image filesystem |
| Go modules | ELF binaries with embedded Go module build info | No `go.mod` or `go.sum` matcher; only compiled binaries, not source-tree manifests |

### Native vs delegated parsing

**Delegated** ecosystems hand extracted file contents to a separate Snyk language parser npm package and take `identity.type` from the returned dep graph’s package-manager name (`depGraph.pkgManager.name`):

- Node — [`node.ts:245`](../lib/analyzer/applications/node.ts)
- PHP — [`php.ts:65`](../lib/analyzer/applications/php.ts)
- Poetry — [`poetry.ts:42`](../lib/analyzer/applications/python/poetry.ts)

**Native** ecosystems are parsed inside this repository and hard-code their `identity.type`:

- pip — literal `'pip'` ([`pip.ts:172`](../lib/analyzer/applications/python/pip.ts))
- .NET — literal `'nuget'` ([`dotnet.ts:115`](../lib/analyzer/applications/dotnet.ts))
- Java — literal `'maven'` ([`java.ts:62`](../lib/analyzer/applications/java.ts)); uses `adm-zip` archive traversal and a properties parser, not a Snyk language parser package
- Go — literal `'gomodules'` ([`lib/go-parser/index.ts:36`, `:205`](../lib/go-parser/index.ts)); in-repo ELF reader

There is no [`lib/analyzer/applications/python.ts`](../lib/analyzer/applications/python.ts); Python consumers live in [`lib/analyzer/applications/python/pip.ts`](../lib/analyzer/applications/python/pip.ts) and [`lib/analyzer/applications/python/poetry.ts`](../lib/analyzer/applications/python/poetry.ts) behind [`lib/analyzer/applications/python/index.ts`](../lib/analyzer/applications/python/index.ts).
