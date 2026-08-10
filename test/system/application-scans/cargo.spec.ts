import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as tar from "tar-stream";

import { scan } from "../../../lib";

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

function createLayerTarball(entryPath: string, content: string) {
  return packToBuffer((pack) => {
    pack.entry({ name: entryPath, type: "file" }, content);
  });
}

async function createTestDockerArchive(
  tempDir: string,
  entryPath: string,
  content: string,
): Promise<string> {
  const layerTarball = await createLayerTarball(entryPath, content);
  const layerName = "layer0.tar";
  const manifest = [
    { Config: CONFIG_FILE_NAME, RepoTags: [], Layers: [layerName] },
  ];
  const config = {
    rootfs: {
      type: "layers",
      diff_ids: [`sha256:${"b".repeat(64)}`],
    },
  };

  const archive = await packToBuffer((pack) => {
    pack.entry({ name: "manifest.json" }, JSON.stringify(manifest));
    pack.entry({ name: CONFIG_FILE_NAME }, JSON.stringify(config));
    pack.entry({ name: layerName }, layerTarball);
  });

  const archivePath = path.join(tempDir, `cargo-test-image-${Date.now()}.tar`);
  fs.writeFileSync(archivePath, archive);
  return archivePath;
}

describe("cargo application scans", () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "cargo-scan-test-"));
  });

  afterAll(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("scans a Cargo.lock found in a docker-archive image", async () => {
    const lockContent = fs.readFileSync(
      path.join(__dirname, "../../fixtures/cargo/standard/Cargo.lock"),
      "utf8",
    );
    const archivePath = await createTestDockerArchive(
      tempDir,
      "app/Cargo.lock",
      lockContent,
    );

    const pluginResult = await scan({
      path: `docker-archive:${archivePath}`,
      "app-vulns": true,
    });

    const cargoResults = pluginResult.scanResults.filter(
      (result) => result.identity.type === "cargo",
    );

    expect(cargoResults).toHaveLength(1);

    const [cargoResult] = cargoResults;
    const depGraphFact = cargoResult.facts.find(
      (fact) => fact.type === "depGraph",
    );

    expect({
      identity: cargoResult.identity,
      depGraph: depGraphFact?.data.toJSON(),
    }).toMatchSnapshot();
  });
});
