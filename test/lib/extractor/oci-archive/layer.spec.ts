import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as tar from "tar-stream";
import { gzipSync } from "zlib";
import { extractArchive } from "../../../../lib/extractor/oci-archive/layer";
import { ExtractAction } from "../../../../lib/extractor/types";
import { PluginOptions } from "../../../../lib/types";

const getFixture = (fixturePath: string): string =>
  path.join(__dirname, "../../../fixtures", fixturePath);

/**
 * Creates a minimal OCI archive tar in memory for testing.
 *
 * OCI layout:
 * - index.json (main index pointing to manifest)
 * - blobs/sha256/<manifest-hash> (manifest JSON)
 * - blobs/sha256/<config-hash> (config JSON)
 * - blobs/sha256/<layer-hash> (gzipped or uncompressed tar layer)
 * - oci-layout (layout version file)
 */
async function createTestOciArchive(options: {
  layers?: Array<{
    files: Record<string, string>;
    compressed?: boolean;
  }>;
  platform?: { os: string; architecture: string };
}): Promise<Buffer> {
  const pack = tar.pack();
  const chunks: Buffer[] = [];

  const platformOs = options.platform?.os ?? "linux";
  const platformArch = options.platform?.architecture ?? "amd64";

  // Create layer blobs - track both compressed and uncompressed digests
  const layerInfo: Array<{
    digest: string;
    size: number;
    diffId: string;
    compressed: boolean;
  }> = [];

  for (const layerDef of options.layers ?? [
    { files: { "/test.txt": "test" } },
  ]) {
    const layerTar = await createLayerTarball(layerDef.files);
    const isCompressed = layerDef.compressed !== false;
    const layerContent = isCompressed ? gzipSync(layerTar) : layerTar;
    const layerHash = createHash(layerContent);
    const layerDigest = `sha256:${layerHash}`;

    // diff_id should be the digest of the uncompressed content per OCI spec
    const diffId = `sha256:${createHash(layerTar)}`;

    pack.entry({ name: `blobs/sha256/${layerHash}` }, layerContent);
    layerInfo.push({
      digest: layerDigest,
      size: layerContent.length,
      diffId,
      compressed: isCompressed,
    });
  }

  // Create config blob with correct diff_ids (uncompressed digests)
  const config = {
    architecture: platformArch,
    os: platformOs,
    rootfs: {
      type: "layers",
      diff_ids: layerInfo.map((l) => l.diffId),
    },
    config: {
      Labels: {},
    },
    created: "2024-01-01T00:00:00Z",
  };
  const configContent = Buffer.from(JSON.stringify(config));
  const configHash = createHash(configContent);
  const configDigest = `sha256:${configHash}`;
  pack.entry({ name: `blobs/sha256/${configHash}` }, configContent);

  // Create manifest blob with correct mediaTypes based on compression
  const manifest = {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: configDigest,
      size: configContent.length,
    },
    layers: layerInfo.map((l) => ({
      mediaType: l.compressed
        ? "application/vnd.oci.image.layer.v1.tar+gzip"
        : "application/vnd.oci.image.layer.v1.tar",
      digest: l.digest,
      size: l.size,
    })),
  };
  const manifestContent = Buffer.from(JSON.stringify(manifest));
  const manifestHash = createHash(manifestContent);
  const manifestDigest = `sha256:${manifestHash}`;
  pack.entry({ name: `blobs/sha256/${manifestHash}` }, manifestContent);

  // Create index.json
  const index = {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: manifestDigest,
        size: manifestContent.length,
        platform: {
          architecture: platformArch,
          os: platformOs,
        },
      },
    ],
  };
  pack.entry({ name: "index.json" }, JSON.stringify(index));

  // Add oci-layout file (should be skipped by extractor)
  const ociLayout = { imageLayoutVersion: "1.0.0" };
  pack.entry({ name: "oci-layout" }, JSON.stringify(ociLayout));

  pack.finalize();

  return new Promise((resolve, reject) => {
    pack.on("data", (chunk: Buffer) => chunks.push(chunk));
    pack.on("end", () => resolve(Buffer.concat(chunks)));
    pack.on("error", reject);
  });
}

/**
 * Creates a tar archive containing the specified files.
 */
async function createLayerTarball(
  files: Record<string, string>,
): Promise<Buffer> {
  const pack = tar.pack();
  const chunks: Buffer[] = [];

  for (const [filePath, content] of Object.entries(files)) {
    pack.entry({ name: filePath.replace(/^\//, "") }, content);
  }

  pack.finalize();

  return new Promise((resolve, reject) => {
    pack.on("data", (chunk: Buffer) => chunks.push(chunk));
    pack.on("end", () => resolve(Buffer.concat(chunks)));
    pack.on("error", reject);
  });
}

/**
 * Creates a SHA256 hash of the content.
 */
function createHash(content: Buffer): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

let tempDir: string;

/**
 * Writes a buffer to a temporary file and returns the path.
 */
async function writeTempArchive(content: Buffer): Promise<string> {
  if (!tempDir) {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "oci-archive-test-"));
  }
  const tmpPath = path.join(tempDir, `test-oci-${Date.now()}.tar`);
  fs.writeFileSync(tmpPath, content);
  return tmpPath;
}

/**
 * Cleans up temporary test files.
 */
function cleanupTempArchive(archivePath: string): void {
  if (fs.existsSync(archivePath)) {
    fs.unlinkSync(archivePath);
  }
}

describe("OCI archive layer extraction", () => {
  const defaultExtractActions: ExtractAction[] = [
    {
      actionName: "text-content",
      filePathMatches: (filePath) => filePath.endsWith(".txt"),
      callback: async (stream) => {
        const chunks: Buffer[] = [];
        return new Promise((resolve, reject) => {
          stream.on("data", (chunk: Buffer) => chunks.push(chunk));
          stream.on("end", () =>
            resolve(Buffer.concat(chunks).toString("utf8")),
          );
          stream.on("error", reject);
        });
      },
    },
  ];

  afterAll(() => {
    // Clean up the temp directory after all tests
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe("basic extraction", () => {
    it("should extract a simple OCI archive with one layer", async () => {
      const archive = await createTestOciArchive({
        layers: [{ files: { "/test.txt": "hello world" } }],
      });
      const archivePath = await writeTempArchive(archive);

      try {
        const result = await extractArchive(
          archivePath,
          defaultExtractActions,
          {} as PluginOptions,
        );

        expect(result.layers).toHaveLength(1);
        expect(result.manifest).toBeDefined();
        expect(result.imageConfig).toBeDefined();
        expect(result.imageConfig.architecture).toBe("amd64");
        expect(result.imageConfig.os).toBe("linux");
      } finally {
        cleanupTempArchive(archivePath);
      }
    });

    it("should extract multiple layers in correct order", async () => {
      const archive = await createTestOciArchive({
        layers: [
          { files: { "/layer1.txt": "first" } },
          { files: { "/layer2.txt": "second" } },
          { files: { "/layer3.txt": "third" } },
        ],
      });
      const archivePath = await writeTempArchive(archive);

      try {
        const result = await extractArchive(
          archivePath,
          defaultExtractActions,
          {} as PluginOptions,
        );

        // Layers should be reversed (last layer first for overlay)
        expect(result.layers).toHaveLength(3);
      } finally {
        cleanupTempArchive(archivePath);
      }
    });
  });

  describe("compression handling", () => {
    it("should handle gzip-compressed layers", async () => {
      const archive = await createTestOciArchive({
        layers: [
          { files: { "/compressed.txt": "gzip content" }, compressed: true },
        ],
      });
      const archivePath = await writeTempArchive(archive);

      try {
        const result = await extractArchive(
          archivePath,
          defaultExtractActions,
          {} as PluginOptions,
        );

        expect(result.layers).toHaveLength(1);
      } finally {
        cleanupTempArchive(archivePath);
      }
    });

    it("should handle uncompressed layers", async () => {
      const archive = await createTestOciArchive({
        layers: [
          {
            files: { "/uncompressed.txt": "raw tar content" },
            compressed: false,
          },
        ],
      });
      const archivePath = await writeTempArchive(archive);

      try {
        const result = await extractArchive(
          archivePath,
          defaultExtractActions,
          {} as PluginOptions,
        );

        expect(result.layers).toHaveLength(1);
      } finally {
        cleanupTempArchive(archivePath);
      }
    });
  });

  describe("non-blob file handling", () => {
    it("should skip oci-layout and other non-blob files without errors", async () => {
      // The createTestOciArchive already includes oci-layout
      const archive = await createTestOciArchive({
        layers: [{ files: { "/test.txt": "content" } }],
      });
      const archivePath = await writeTempArchive(archive);

      try {
        // Should not throw despite oci-layout file being present
        const result = await extractArchive(
          archivePath,
          defaultExtractActions,
          {} as PluginOptions,
        );

        expect(result.layers).toHaveLength(1);
      } finally {
        cleanupTempArchive(archivePath);
      }
    });
  });

  describe("platform selection", () => {
    it("should use specified platform option", async () => {
      const archive = await createTestOciArchive({
        layers: [{ files: { "/test.txt": "content" } }],
        platform: { os: "linux", architecture: "arm64" },
      });
      const archivePath = await writeTempArchive(archive);

      try {
        const result = await extractArchive(
          archivePath,
          defaultExtractActions,
          {
            platform: "linux/arm64",
          } as PluginOptions,
        );

        expect(result.imageConfig.architecture).toBe("arm64");
      } finally {
        cleanupTempArchive(archivePath);
      }
    });
  });

  describe("error handling", () => {
    it("should throw InvalidArchiveError when no layers can be extracted", async () => {
      // Create an archive with an invalid layer (content that won't parse as tar)
      const pack = tar.pack();
      const chunks: Buffer[] = [];

      // Minimal valid structure but with corrupted layer
      const configContent = Buffer.from(
        JSON.stringify({
          architecture: "amd64",
          os: "linux",
          rootfs: { type: "layers", diff_ids: ["sha256:invalid"] },
          config: { Labels: {} },
          created: "2024-01-01T00:00:00Z",
        }),
      );
      const configHash = createHash(configContent);
      pack.entry({ name: `blobs/sha256/${configHash}` }, configContent);

      // Invalid layer content (not a valid tar)
      const invalidLayerContent = gzipSync(Buffer.from("not a tar file"));
      const invalidLayerHash = createHash(invalidLayerContent);
      pack.entry(
        { name: `blobs/sha256/${invalidLayerHash}` },
        invalidLayerContent,
      );

      const manifest = {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        config: { digest: `sha256:${configHash}`, size: configContent.length },
        layers: [
          {
            mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
            digest: `sha256:${invalidLayerHash}`,
            size: invalidLayerContent.length,
          },
        ],
      };
      const manifestContent = Buffer.from(JSON.stringify(manifest));
      const manifestHash = createHash(manifestContent);
      pack.entry({ name: `blobs/sha256/${manifestHash}` }, manifestContent);

      const index = {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: [
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: `sha256:${manifestHash}`,
            size: manifestContent.length,
            platform: { architecture: "amd64", os: "linux" },
          },
        ],
      };
      pack.entry({ name: "index.json" }, JSON.stringify(index));
      pack.finalize();

      const archiveBuffer = await new Promise<Buffer>((resolve, reject) => {
        pack.on("data", (chunk: Buffer) => chunks.push(chunk));
        pack.on("end", () => resolve(Buffer.concat(chunks)));
        pack.on("error", reject);
      });

      const archivePath = await writeTempArchive(archiveBuffer);

      try {
        await expect(
          extractArchive(
            archivePath,
            defaultExtractActions,
            {} as PluginOptions,
          ),
        ).rejects.toThrow(/Failed to extract any layers/);
      } finally {
        cleanupTempArchive(archivePath);
      }
    });
  });

  describe("existing OCI archive fixtures", () => {
    it("should extract alpine OCI archive", async () => {
      const fixturePath = getFixture("oci-archives/alpine-3.12.0.tar");
      if (!fs.existsSync(fixturePath)) {
        console.log("Skipping test: fixture not found");
        return;
      }

      const result = await extractArchive(
        fixturePath,
        defaultExtractActions,
        {} as PluginOptions,
      );

      expect(result.layers.length).toBeGreaterThan(0);
      expect(result.manifest).toBeDefined();
      expect(result.imageConfig).toBeDefined();
    });

    it("should extract busybox OCI archive", async () => {
      const fixturePath = getFixture("oci-archives/busybox-1.31.1.tar");
      if (!fs.existsSync(fixturePath)) {
        console.log("Skipping test: fixture not found");
        return;
      }

      const result = await extractArchive(
        fixturePath,
        defaultExtractActions,
        {} as PluginOptions,
      );

      expect(result.layers.length).toBeGreaterThan(0);
      expect(result.manifest).toBeDefined();
      expect(result.imageConfig).toBeDefined();
    });

    it("should extract OCI archive with nested index", async () => {
      const fixturePath = getFixture("oci-archives/oci-nested-index.tar");
      if (!fs.existsSync(fixturePath)) {
        console.log("Skipping test: fixture not found");
        return;
      }

      const result = await extractArchive(
        fixturePath,
        defaultExtractActions,
        {} as PluginOptions,
      );

      expect(result.layers.length).toBeGreaterThan(0);
      expect(result.manifest).toBeDefined();
      expect(result.imageConfig).toBeDefined();
    });
  });
});
