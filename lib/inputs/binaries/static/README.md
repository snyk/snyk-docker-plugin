# Static key-binary hash tables

## Regenerating the .NET shared framework table

Run the generator from the repository root:

```bash
npx ts-node scripts/update-dotnet-key-binary-hashes.ts
```

Optional flags:

- `--channel <major.minor>` — release-metadata channel to read (repeatable; default: `8.0`, `9.0`)
- `--version <x.y.z>` — explicit runtime version to include (repeatable; default: latest stable patch per channel)
- `--rid <rid>` — runtime identifier to download (repeatable; default: `linux-x64`, `linux-arm64`, `linux-musl-x64`)
- `--output <path>` — output module path (default: `lib/inputs/binaries/static/dotnet-shared-framework-hashes.ts`)

Example for one version and RID:

```bash
npx ts-node scripts/update-dotnet-key-binary-hashes.ts \
  --channel 8.0 \
  --version 8.0.30 \
  --rid linux-x64
```

## Upstream metadata

The generator reads Microsoft release metadata from:

`https://builds.dotnet.microsoft.com/dotnet/release-metadata/<channel>/releases.json`

Archive URLs in that metadata point at official runtime tarballs on `builds.dotnet.microsoft.com`.

## Hashed files

Inside each downloaded `dotnet-runtime-*-linux-*.tar.gz` archive, the generator hashes these files under `shared/Microsoft.NETCore.App/<version>/`:

- `libcoreclr.so`
- `System.Private.CoreLib.dll`

Those names match what `getDotnetBinariesFileContentAction` collects from container images.

## Build provenance

Hashes in the committed table come from official `builds.dotnet.microsoft.com` runtime tarballs — the same provisioning path used by `mcr.microsoft.com/dotnet/*` images. .NET installed from distro packages (`dotnet-runtime-8.0` via apt/apk/rpm, including Red Hat rebuilds) is built differently and is outside this table's coverage.

## Re-verifying one committed hash by hand

1. Copy a `sources` URL from an entry in `dotnet-shared-framework-hashes.ts`.
2. Download and extract the tarball, for example:

   ```bash
   curl -fsSL -o runtime.tar.gz '<source-url>'
   tar -xzf runtime.tar.gz 'shared/Microsoft.NETCore.App/*/<binary>'
   ```

3. Hash the extracted file:

   ```bash
   sha256sum shared/Microsoft.NETCore.App/*/<binary>
   ```

4. Compare the lowercase hex digest to the table key for that entry.
