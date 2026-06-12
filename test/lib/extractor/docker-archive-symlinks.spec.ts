import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as tar from "tar-stream";
import { extractImageContent } from "../../../lib/extractor";
import { ImageType } from "../../../lib/types";

interface LayerEntry {
  name: string;
  type?: "file" | "symlink" | "link";
  linkname?: string;
  content?: string;
}

const CONFIG_FILE_NAME = `${"a".repeat(64)}.json`;

async function packToBuffer(
  addEntries: (pack: tar.Pack) => void,
): Promise<Buffer> {
  const pack = tar.pack();
  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    pack.on("data", (chunk: Buffer) => chunks.push(chunk));
    pack.on("end", () => resolve(Buffer.concat(chunks)));
    pack.on("error", reject);
  });
  addEntries(pack);
  pack.finalize();
  return done;
}

function createLayerTarball(entries: LayerEntry[]): Promise<Buffer> {
  return packToBuffer((pack) => {
    for (const entry of entries) {
      if (entry.type === "symlink" || entry.type === "link") {
        pack.entry({
          name: entry.name,
          type: entry.type,
          linkname: entry.linkname,
        });
      } else {
        pack.entry({ name: entry.name, type: "file" }, entry.content ?? "");
      }
    }
  });
}

/**
 * Builds a minimal docker-archive tar in memory: manifest.json, a config
 * file, and one tarball per layer. Layers are given base-first, matching
 * the order of manifest.json's Layers field in a real docker save archive.
 */
async function createTestDockerArchive(
  layers: LayerEntry[][],
): Promise<string> {
  const layerTarballs = await Promise.all(layers.map(createLayerTarball));
  const layerNames = layers.map((_, i) => `layer${i}.tar`);
  const manifest = [
    { Config: CONFIG_FILE_NAME, RepoTags: [], Layers: layerNames },
  ];
  const config = {
    rootfs: {
      type: "layers",
      diff_ids: layers.map((_, i) => `sha256:${"b".repeat(63)}${i}`),
    },
  };

  const archive = await packToBuffer((pack) => {
    pack.entry({ name: "manifest.json" }, JSON.stringify(manifest));
    pack.entry({ name: CONFIG_FILE_NAME }, JSON.stringify(config));
    layerTarballs.forEach((tarball, i) => {
      pack.entry({ name: layerNames[i] }, tarball);
    });
  });

  const archivePath = path.join(tempDir, `test-image-${Date.now()}.tar`);
  fs.writeFileSync(archivePath, archive);
  return archivePath;
}

let tempDir: string;

describe("docker-archive symlink extraction across layers", () => {
  beforeAll(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "docker-archive-test-"));
  });

  afterAll(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("uses the upper layer's symlink when it replaces a base-layer symlink", async () => {
    const archivePath = await createTestDockerArchive([
      // base layer
      [{ name: "bin", type: "symlink", linkname: "usr/old-bin" }],
      // upper layer
      [{ name: "bin", type: "symlink", linkname: "usr/new-bin" }],
    ]);

    const result = await extractImageContent(
      ImageType.DockerArchive,
      archivePath,
      [],
      {},
    );

    expect(result.symlinks).toEqual({ "/bin": "/usr/new-bin" });
  });

  it("drops a base-layer symlink deleted by an upper-layer whiteout", async () => {
    const archivePath = await createTestDockerArchive([
      // base layer
      [
        { name: "bin", type: "symlink", linkname: "usr/bin" },
        { name: "lib", type: "symlink", linkname: "usr/lib" },
      ],
      // upper layer deletes /bin
      [{ name: ".wh.bin", type: "file" }],
    ]);

    const result = await extractImageContent(
      ImageType.DockerArchive,
      archivePath,
      [],
      {},
    );

    expect(result.symlinks).toEqual({ "/lib": "/usr/lib" });
  });

  it("keeps a base-layer symlink untouched by upper layers", async () => {
    const archivePath = await createTestDockerArchive([
      // base layer
      [{ name: "lib", type: "symlink", linkname: "usr/lib" }],
      // upper layer adds an unrelated file
      [{ name: "etc/hostname", type: "file", content: "myhost\n" }],
    ]);

    const result = await extractImageContent(
      ImageType.DockerArchive,
      archivePath,
      [],
      {},
    );

    expect(result.symlinks).toEqual({ "/lib": "/usr/lib" });
  });
});
