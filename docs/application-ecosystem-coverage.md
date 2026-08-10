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
| **PHP / Composer** | Supported | `composer.json`, `composer.lock`, and `vendor/composer/installed.json` (anchored on the `vendor/composer/` path segment) ([`lib/inputs/php/static.ts:6-13`](../lib/inputs/php/static.ts)) | [`lib/inputs/php/static.ts`](../lib/inputs/php/static.ts), action `php-app-files` | [`lib/analyzer/applications/php.ts`](../lib/analyzer/applications/php.ts); `identity.type` = `depGraph.pkgManager.name` ([`:75`, `:140`](../lib/analyzer/applications/php.ts)) | **Delegated** for a `composer.json`+`composer.lock` pair — [`@snyk/composer-lockfile-parser`](https://www.npmjs.com/package/@snyk/composer-lockfile-parser) (`package.json:33`); **Native** fallback when only `composer.lock` or only `vendor/composer/installed.json` is present — in-repo [`lib/php-parser/composer-lock-parser.ts`](../lib/php-parser/composer-lock-parser.ts), consumed by `buildScanResultFromPackages` in `php.ts`. A `composer.json` with no `composer.lock` is not reported: it carries version constraints, not pinned versions |
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
- PHP (`composer.json`+`composer.lock` pair only) — [`php.ts:75`](../lib/analyzer/applications/php.ts)
- Poetry — [`poetry.ts:42`](../lib/analyzer/applications/python/poetry.ts)

**Native** ecosystems are parsed inside this repository and hard-code their `identity.type`:

- pip — literal `'pip'` ([`pip.ts:172`](../lib/analyzer/applications/python/pip.ts))
- .NET — literal `'nuget'` ([`dotnet.ts:115`](../lib/analyzer/applications/dotnet.ts))
- Java — literal `'maven'` ([`java.ts:62`](../lib/analyzer/applications/java.ts)); uses `adm-zip` archive traversal and a properties parser, not a Snyk language parser package
- Go — literal `'gomodules'` ([`lib/go-parser/index.ts:36`, `:205`](../lib/go-parser/index.ts)); in-repo ELF reader
- PHP fallback (`composer.lock`-only or `vendor/composer/installed.json`-only) — `identity.type` is still `depGraph.pkgManager.name` ([`php.ts:140`](../lib/analyzer/applications/php.ts)), pinned to `composer`, but the graph is built directly from [`lib/php-parser/composer-lock-parser.ts`](../lib/php-parser/composer-lock-parser.ts) output rather than delegated to `@snyk/composer-lockfile-parser`

There is no [`lib/analyzer/applications/python.ts`](../lib/analyzer/applications/python.ts); Python consumers live in [`lib/analyzer/applications/python/pip.ts`](../lib/analyzer/applications/python/pip.ts) and [`lib/analyzer/applications/python/poetry.ts`](../lib/analyzer/applications/python/poetry.ts) behind [`lib/analyzer/applications/python/index.ts`](../lib/analyzer/applications/python/index.ts).

## Not detected

The following ecosystems named in the request against Snyk Open Source's supported application-manifest ecosystems have **no** extract action and **no** analyzer anywhere under `lib/`. Each claim below is falsifiable by the searches in the [Evidence appendix](#evidence-appendix): searching `lib/` for the manifest filenames associated with each ecosystem returns no code that reads them from the image filesystem.

| Ecosystem | Manifest(s) that would indicate support | Result of searching `lib/` |
| --- | --- | --- |
| RubyGems / Bundler | `Gemfile`, `Gemfile.lock`, `*.gemspec` | No `ExtractAction` matches these names. The only hit for `Gemfile` anywhere in `lib/` is a code comment ([`lib/types.ts:64`](../lib/types.ts)) naming `Gemfile.lock` as an example manifest in a type description; it is not read from an image |
| Cargo (Rust) | `Cargo.toml`, `Cargo.lock` | No hits, no `ExtractAction`, no analyzer |
| CocoaPods | `Podfile`, `Podfile.lock`, `*.podspec` | No hits, no `ExtractAction`, no analyzer |
| Swift Package Manager | `Package.swift` | No hits, no `ExtractAction`, no analyzer |
| Hex / Elixir | `mix.exs`, `mix.lock` | No hits, no `ExtractAction`, no analyzer |
| Dart / Pub | `pubspec.yaml`, `pubspec.lock` | No hits, no `ExtractAction`, no analyzer |
| Scala / sbt | `build.sbt`, `*.sbt` | No hits, no `ExtractAction`, no analyzer |
| NuGet — manifest half | `packages.config`, `paket.lock`, `packages.lock.json`, `*.csproj` | No hits for `paket` or `packages.config`; NuGet detection ([above](#detected)) is limited to published `*.deps.json` |
| Maven/Gradle — manifest half | `pom.xml`, `build.gradle` | No hits for `pom.xml` or `build.gradle` as filesystem matchers; Java/Maven detection ([above](#detected)) reads coordinates only from `pom.properties` inside already-extracted `.jar`/`.war` archives |

`Pipfile` (Pipenv's manifest) is a partial exception: it appears once in `lib/`, in `pythonApplicationFileSuffixes` ([`lib/inputs/python/static.ts:13`](../lib/inputs/python/static.ts)). That list feeds `collect-application-files`, a source-file collection path used for reporting which application files exist on the image — it is not consumed by any dependency-graph analyzer, and no `Pipfile.lock` matcher or Pipenv analyzer exists. So Pipenv dependencies are not detected even though the bare filename `Pipfile` is recognised for an unrelated purpose.

### Completeness against Snyk Open Source's supported ecosystems

This document could not fetch or verify Snyk Open Source's current supported-ecosystem list from a live source (this audit is limited to static inspection of this repository, with no network access). The ecosystems covered above are therefore exactly the set named in the originating request — npm/yarn/pnpm, pip/Poetry/Pipenv, Maven/Gradle, RubyGems/Bundler, NuGet/Paket, Composer, Go modules, Cargo, and CocoaPods — plus Swift, Hex/Elixir, Dart/Pub, and Scala/sbt added here because they are commonly listed as Snyk Open Source application ecosystems and their absence is worth stating explicitly rather than by omission. If Snyk Open Source supports an application ecosystem not named above, this document does not cover it, and that gap is itself a caveat (see [Caveats](#caveats)) rather than a verified "not detected" claim.

## Evidence appendix

Two greps against `lib/` were run to check whether any manifest-filename string for the "not detected" ecosystems appears anywhere in the source, including places that would not by themselves indicate real detection (comments, unrelated identifiers). Both are reproducible with the commands below; a reviewer re-running them should see the same hit counts and locations.

**Check A — narrow manifest-filename sweep.** Pattern (case-insensitive): `Gemfile|gemspec|Cargo\.toml|Podfile|packages\.config|paket|pubspec|mix\.exs|Package\.swift|\.sbt|pom\.xml|build\.gradle`

This returns exactly **one** hit in the whole of `lib/`:

- [`lib/types.ts:64`](../lib/types.ts) — a code comment reading `// Package manager manifests (e.g. requirements.txt, Gemfile.lock) collected as part of an application scan.` This is a comment on a type describing collected manifest filenames for reporting purposes, not an `ExtractAction` matcher; it does not indicate Gemfile detection.

Notably, this narrow pattern does **not** match [`lib/inputs/java/static.ts:6`](../lib/inputs/java/static.ts) (`const ignoredPaths = [usrLibPath, "gradle/cache"];`), because that line contains the bare substring `gradle` without `build.gradle`, and the pattern does not include bare `gradle`.

**Check B — broadened sweep.** Pattern (case-insensitive), narrow pattern plus bare `gradle|maven|nuget`: `Gemfile|gemspec|Cargo\.toml|Podfile|packages\.config|paket|pubspec|mix\.exs|Package\.swift|\.sbt|pom\.xml|build\.gradle|gradle|maven|nuget`

This returns **nine** hits in `lib/`, none of which are filesystem manifest matchers:

- [`lib/types.ts:64`](../lib/types.ts) — the same comment as Check A
- [`lib/inputs/java/static.ts:6`](../lib/inputs/java/static.ts) — `ignoredPaths` list excluding `gradle/cache` from `.jar`/`.war` matching, not a Gradle manifest matcher
- [`lib/analyzer/applications/dotnet.ts:54`](../lib/analyzer/applications/dotnet.ts) — a comment about the canonical NuGet id format
- [`lib/analyzer/applications/dotnet.ts:115`](../lib/analyzer/applications/dotnet.ts) — the literal `identity.type: "nuget"` already documented in the Detected table above
- [`lib/analyzer/applications/dotnet.ts:171`](../lib/analyzer/applications/dotnet.ts) — `{ name: "nuget" }`, part of the same identity, not a new matcher
- [`lib/analyzer/applications/java.ts:62`](../lib/analyzer/applications/java.ts) — the literal `identity.type: "maven"` already documented above
- [`lib/analyzer/applications/java.ts:200`](../lib/analyzer/applications/java.ts) — a comment about reducing dependence on Maven Central search
- [`lib/analyzer/applications/java.ts:230`](../lib/analyzer/applications/java.ts) — a comment about the sha1 fallback for Maven Central
- [`lib/analyzer/applications/java.ts:258`](../lib/analyzer/applications/java.ts) — a comment about resolving JARs via "maven-deps"

None of the nine hits is a `pom.xml`, `build.gradle`, `packages.config`, or `paket` filesystem matcher. This confirms the "manifest half" gaps stated in the [Detected](#detected) table and the [Not detected](#not-detected) table above.

## Caveats

- **No network access at audit time.** This document is built entirely from static inspection of this repository's source at the commit it was written against. It could not cross-check against Snyk Open Source's live supported-ecosystem documentation; see [Completeness against Snyk Open Source's supported ecosystems](#completeness-against-snyk-open-sources-supported-ecosystems).
- **Gate assumed open.** All "Detected" rows assume `exclude-app-vulns` is unset/false. If a caller sets `exclude-app-vulns`, none of the application-ecosystem extraction or analysis described here runs, and every ecosystem — including the ones in the Detected table — behaves as "not detected" for that scan.
- **Runtime-only signal for Go.** Go module detection depends on binaries retaining embedded build info (`.go.buildinfo` / `.note.go.buildid` ELF sections); a stripped binary or a Go source tree with only `go.mod`/`go.sum` on the image filesystem produces no detection, even though the ecosystem is nominally "supported" here.
- **Partial support is not full support.** The "Partially supported" rows in the Detected table (.NET/NuGet, Java/Maven, Go modules) detect only the code paths named there. A manifest-only project (e.g. a `.csproj` with no published `*.deps.json`, or a Java source tree with a `pom.xml` but no built `.jar`/`.war`) is not detected despite the ecosystem having a row in that table.
- **This document does not change plugin behavior.** It is an audit artifact only; none of the gaps identified here have been fixed as part of producing this document.
