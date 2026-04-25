import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as tar from "tar-stream";
import { gzipSync } from "zlib";
import {
  extractImageContent,
  InvalidArchiveError,
} from "../../../lib/extractor";
import { ExtractionResult } from "../../../lib/extractor/types";
import { getRedHatRepositoriesContentAction } from "../../../lib/inputs/redHat/static";
import { ImageType } from "../../../lib/types";
import { getFixture } from "../../util/index";

describe("extractImageContent", () => {
  let extractedContent: ExtractionResult;

  beforeAll(async () => {
    extractedContent = await extractImageContent(
      ImageType.DockerArchive,
      getFixture("docker-archives/docker-save/nginx-with-buildinfo.tar"),
      [getRedHatRepositoriesContentAction],
      {},
    );
  });

  it("extracts image labels", async () => {
    expect(extractedContent.imageLabels).toMatchObject({
      maintainer: "NGINX Docker Maintainers <docker-maint@nginx.com>",
    });
  });

  it("extracts image creation time", async () => {
    expect(typeof extractedContent.imageCreationTime).toEqual("string");
  });

  describe("RedHat support", () => {
    it("extracts red hat repositories information from layers", async () => {
      const numOfFoundFiles = Object.keys(
        extractedContent.extractedLayers,
      ).length;
      expect(numOfFoundFiles).toBe(1);

      expect(
        extractedContent.extractedLayers[
          "/root/buildinfo/content_manifests/jenkins-agent-maven-35-rhel7-container-v3.11.346-2.json"
        ]["redhat-content-manifests"],
      ).toMatchObject({
        metadata: {
          icm_version: 1,
          icm_spec:
            "https://raw.githubusercontent.com/containerbuildsystem/atomic-reactor/master/atomic_reactor/schemas/content_manifest.json",
          image_layer_index: 6,
        },
        content_sets: [
          "rhel-7-server-ose-3.11-rpms",
          "rhel-server-rhscl-7-rpms",
          "rhel-7-server-rpms",
        ],
        image_contents: [],
      });
    });
  });

  describe("OCI Image Archives (expected to fall back to DockerExtractor)", () => {
    const fixture = getFixture("containerd-archives/alpine.tar");
    const opts = { platform: "linux/amd64" };

    it("successfully extracts the archive when image type is set to oci-archive", async () => {
      await expect(
        extractImageContent(ImageType.OciArchive, fixture, [], opts),
      ).resolves.not.toThrow();
    });

    it("successfully extracts the archive when image type is not set", async () => {
      await expect(
        extractImageContent(0, fixture, [], opts),
      ).resolves.not.toThrow();
    });

    it("successfully extracts the archive when image type is set to docker-archive", async () => {
      await expect(
        extractImageContent(ImageType.DockerArchive, fixture, [], opts),
      ).resolves.not.toThrow();
    });
  });

  describe("Kaniko Image Archives", () => {
    const fixture = getFixture("kaniko-archives/kaniko-busybox.tar");
    const opts = { platform: "linux/amd64" };

    it("successfully extracts the archive when image type is set to kaniko-archive", async () => {
      await expect(
        extractImageContent(ImageType.KanikoArchive, fixture, [], opts),
      ).resolves.not.toThrow();
    });
  });

  describe("Images pulled & saved with Docker Engine >= 25.x", () => {
    const type = ImageType.OciArchive;

    it("extracts when using default platform flag (linux/amd64)", async () => {
      const fixture = getFixture("docker-oci-archives/busybox.amd64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/amd64" }),
      ).resolves.not.toThrow();
    });

    it("extracts when using non-default platform flag with no variant (linux/arm64)", async () => {
      const fixture = getFixture("docker-oci-archives/busybox.arm64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/arm64" }),
      ).resolves.not.toThrow();
    });

    it("extracts when using non-default platform flag with variant (linux/arm64/v8)", async () => {
      const fixture = getFixture("docker-oci-archives/busybox.arm64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/arm64/v8" }),
      ).resolves.not.toThrow();
    });
  });

  describe("Images pulled & saved with containerd", () => {
    const type = ImageType.OciArchive;

    it("extracts when using default platform flag (--platform=linux/amd64)", async () => {
      const fixture = getFixture("containerd-archives/busybox.amd64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/amd64" }),
      ).resolves.not.toThrow();
    });

    it("extracts when single variant exist for architecture with no variant in platform tag (--platform=linux/arm64)", async () => {
      const fixture = getFixture("containerd-archives/busybox.arm64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/arm64" }),
      ).resolves.not.toThrow();
    });

    describe("with multi-platform images", () => {
      it("extracts when multiple variants exist with same architecture in image (--platform=linux/arm/v7)", async () => {
        const fixture = getFixture("containerd-archives/busybox.multi.tar");
        await expect(
          extractImageContent(type, fixture, [], { platform: "linux/arm/v7" }),
        ).resolves.not.toThrow();
      });

      it("fails when multiple variants exist with same architecture in image with no variant is supplied (--platform=linux/arm)", async () => {
        const fixture = getFixture("containerd-archives/busybox.multi.tar");
        await expect(
          extractImageContent(type, fixture, [], { platform: "linux/arm" }),
        ).rejects.toThrow();
      });

      it("fails when variant does not exist in image (--platform=linux/arm/v4)", async () => {
        const fixture = getFixture("containerd-archives/busybox.multi.tar");
        await expect(
          extractImageContent(type, fixture, [], { platform: "linux/arm/v4" }),
        ).rejects.toThrow();
      });

      it("succeeds for single platform image containing an attestation manifest", async () => {
        const fixture = getFixture(
          "containerd-archives/busybox-single-arch-with-attestation-manifest.tar",
        );
        await expect(
          extractImageContent(type, fixture, [], {}),
        ).resolves.not.toThrow();
      });
    });
  });
});

// ---------------------------------------------------------------------------
// Helpers for in-memory OCI archive creation
// ---------------------------------------------------------------------------

function sha256(content: Buffer): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

async function makeTarLayer(files: Record<string, string>): Promise<Buffer> {
  const pack = tar.pack();
  const chunks: Buffer[] = [];
  for (const [name, content] of Object.entries(files)) {
    pack.entry({ name: name.replace(/^\//, "") }, content);
  }
  pack.finalize();
  return new Promise((resolve, reject) => {
    pack.on("data", (c: Buffer) => chunks.push(c));
    pack.on("end", () => resolve(Buffer.concat(chunks)));
    pack.on("error", reject);
  });
}

interface OciArchiveOptions {
  /** Files to put in the single layer */
  layerFiles?: Record<string, string>;
  /** Annotations on the manifest blob itself */
  manifestAnnotations?: Record<string, string>;
  /** Annotations on the index.json top-level object */
  indexAnnotations?: Record<string, string>;
  /** Annotations on the OciManifestInfo entry inside index.json manifests[] */
  manifestInfoAnnotations?: Record<string, string>;
  /** Labels inside config.Labels */
  configLabels?: Record<string, string>;
}

/**
 * Assembles a minimal OCI archive in memory and writes it to a temp file.
 * Returns the path; caller is responsible for deleting it.
 */
async function buildOciArchive(opts: OciArchiveOptions = {}): Promise<string> {
  const pack = tar.pack();
  const archiveChunks: Buffer[] = [];

  // 1. Layer
  const layerTar = await makeTarLayer(
    opts.layerFiles ?? { "hello.txt": "hello" },
  );
  const layerGz = gzipSync(layerTar);
  const layerHash = sha256(layerGz);
  const layerDigest = `sha256:${layerHash}`;
  pack.entry({ name: `blobs/sha256/${layerHash}` }, layerGz);

  // 2. Config – omit Labels entirely when not provided so that
  // config.Labels is undefined (not null) in the parsed result.
  const configLabels = opts.configLabels;
  const config = {
    architecture: "amd64",
    os: "linux",
    rootfs: { type: "layers", diff_ids: [`sha256:${sha256(layerTar)}`] },
    config: configLabels !== undefined ? { Labels: configLabels } : {},
    created: "2024-01-01T00:00:00Z",
  };
  const configBuf = Buffer.from(JSON.stringify(config));
  const configHash = sha256(configBuf);
  const configDigest = `sha256:${configHash}`;
  pack.entry({ name: `blobs/sha256/${configHash}` }, configBuf);

  // 3. Manifest blob (may carry annotations)
  const manifestBlob: Record<string, unknown> = {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: configDigest,
      size: configBuf.length,
    },
    layers: [
      {
        mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
        digest: layerDigest,
        size: layerGz.length,
      },
    ],
  };
  if (opts.manifestAnnotations) {
    manifestBlob.annotations = opts.manifestAnnotations;
  }
  const manifestBuf = Buffer.from(JSON.stringify(manifestBlob));
  const manifestHash = sha256(manifestBuf);
  const manifestDigest = `sha256:${manifestHash}`;
  pack.entry({ name: `blobs/sha256/${manifestHash}` }, manifestBuf);

  // 4. index.json
  const manifestInfoEntry: Record<string, unknown> = {
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    digest: manifestDigest,
    size: manifestBuf.length,
    platform: { architecture: "amd64", os: "linux" },
  };
  if (opts.manifestInfoAnnotations) {
    manifestInfoEntry.annotations = opts.manifestInfoAnnotations;
  }
  const index: Record<string, unknown> = {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [manifestInfoEntry],
  };
  if (opts.indexAnnotations) {
    index.annotations = opts.indexAnnotations;
  }
  pack.entry({ name: "index.json" }, JSON.stringify(index));
  pack.entry({ name: "oci-layout" }, JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  pack.finalize();

  const archiveBuf = await new Promise<Buffer>((resolve, reject) => {
    pack.on("data", (c: Buffer) => archiveChunks.push(c));
    pack.on("end", () => resolve(Buffer.concat(archiveChunks)));
    pack.on("error", reject);
  });

  const tmpPath = path.join(
    os.tmpdir(),
    `oci-ann-test-${Date.now()}.tar`,
  );
  fs.writeFileSync(tmpPath, archiveBuf);
  return tmpPath;
}

// ---------------------------------------------------------------------------
// OCI annotations integration tests
// ---------------------------------------------------------------------------

describe("OCI annotations in extractImageContent", () => {
  const ociType = ImageType.OciArchive;
  const tempFiles: string[] = [];

  afterAll(() => {
    for (const f of tempFiles) {
      if (fs.existsSync(f)) {
        fs.unlinkSync(f);
      }
    }
  });

  it("exposes OCI manifest blob annotations in imageLabels", async () => {
    const archivePath = await buildOciArchive({
      manifestAnnotations: {
        "org.opencontainers.image.source": "https://github.com/example/repo",
        "org.opencontainers.image.revision": "abc123",
      },
    });
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    expect(result.imageLabels).toBeDefined();
    // Use direct property access; toHaveProperty treats dots as path separators.
    expect(result.imageLabels!["org.opencontainers.image.source"]).toBe(
      "https://github.com/example/repo",
    );
    expect(result.imageLabels!["org.opencontainers.image.revision"]).toBe(
      "abc123",
    );
  });

  it("merges OCI manifest annotations and config Labels into imageLabels", async () => {
    const archivePath = await buildOciArchive({
      manifestAnnotations: {
        "org.opencontainers.image.source": "https://github.com/example/repo",
        team: "platform",
      },
      configLabels: { maintainer: "team@example.com" },
    });
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    expect(result.imageLabels).toBeDefined();
    expect(result.imageLabels!["org.opencontainers.image.source"]).toBe(
      "https://github.com/example/repo",
    );
    expect(result.imageLabels!["team"]).toBe("platform");
    expect(result.imageLabels!["maintainer"]).toBe("team@example.com");
  });

  it("config Labels take precedence over annotations on key collision", async () => {
    const archivePath = await buildOciArchive({
      manifestAnnotations: { team: "from-annotation" },
      configLabels: { team: "from-config-label" },
    });
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    expect(result.imageLabels).toBeDefined();
    expect(result.imageLabels!["team"]).toBe("from-config-label");
  });

  it("imageLabels contains only config Labels when there are no OCI annotations", async () => {
    const archivePath = await buildOciArchive({
      configLabels: { maintainer: "test@example.com", version: "1.0.0" },
    });
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    expect(result.imageLabels).toEqual({
      maintainer: "test@example.com",
      version: "1.0.0",
    });
  });

  it("imageLabels is undefined when there are no annotations and no config Labels", async () => {
    // configLabels: null means config.Labels will be null (not set)
    const archivePath = await buildOciArchive({});
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    // No annotations, config.Labels is null → imageLabels should be undefined
    expect(result.imageLabels).toBeUndefined();
  });

  it("merges index-level and manifest-info-level annotations along with manifest blob annotations", async () => {
    const archivePath = await buildOciArchive({
      indexAnnotations: { "index-level": "from-index" },
      manifestInfoAnnotations: { "manifest-info-level": "from-manifest-info" },
      manifestAnnotations: { "manifest-blob-level": "from-manifest-blob" },
    });
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    expect(result.imageLabels).toBeDefined();
    expect(result.imageLabels!["index-level"]).toBe("from-index");
    expect(result.imageLabels!["manifest-info-level"]).toBe(
      "from-manifest-info",
    );
    expect(result.imageLabels!["manifest-blob-level"]).toBe(
      "from-manifest-blob",
    );
  });

  it("manifest blob annotations override index-level annotations on key collision", async () => {
    const archivePath = await buildOciArchive({
      indexAnnotations: { shared: "from-index", "index-only": "index-value" },
      manifestAnnotations: {
        shared: "from-manifest-blob",
        "manifest-only": "manifest-value",
      },
    });
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    expect(result.imageLabels!["shared"]).toBe("from-manifest-blob");
    expect(result.imageLabels!["index-only"]).toBe("index-value");
    expect(result.imageLabels!["manifest-only"]).toBe("manifest-value");
  });

  it("OCI annotation keys are preserved verbatim (no sanitization)", async () => {
    const archivePath = await buildOciArchive({
      manifestAnnotations: {
        "org.opencontainers.image.source": "https://example.com",
        "com.example.custom-key": "custom-value",
        "io.buildpacks.base.digest": "sha256:deadbeef",
      },
    });
    tempFiles.push(archivePath);

    const result = await extractImageContent(ociType, archivePath, [], {
      platform: "linux/amd64",
    });

    expect(result.imageLabels!["org.opencontainers.image.source"]).toBe(
      "https://example.com",
    );
    expect(result.imageLabels!["com.example.custom-key"]).toBe("custom-value");
    expect(result.imageLabels!["io.buildpacks.base.digest"]).toBe(
      "sha256:deadbeef",
    );
  });
});
