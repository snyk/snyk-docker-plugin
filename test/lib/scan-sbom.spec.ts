import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { scan } from "../../lib/scan";
import { CycloneDxBom } from "../../lib/sbom/cyclonedx";

const SBOM_TARGET_ERROR =
  "--sbom requires a scan target: provide an image identifier or archive path, or a Dockerfile via --file";

describe("scan with --sbom", () => {
  let tmpDir: string;
  let dockerfilePath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-sbom-"));
    dockerfilePath = path.join(tmpDir, "Dockerfile");
    fs.writeFileSync(
      dockerfilePath,
      ["FROM debian:12", "RUN apt-get install -y curl git"].join("\n"),
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("scans a Dockerfile-only target when no image path is provided", async () => {
    const response = await scan({ sbom: true, file: dockerfilePath });

    expect(response.scanResults).toHaveLength(1);

    const [scanResult] = response.scanResults;
    expect(scanResult.identity.type).toBe("dockerfile");
    expect(scanResult.identity.targetFile).toBe(dockerfilePath);
    expect(scanResult.target.image).toBe("debian:12");

    const factTypes = scanResult.facts.map((fact) => fact.type);
    expect(factTypes.filter((type) => type === "sbom")).toHaveLength(1);
    expect(factTypes).toEqual(
      expect.arrayContaining(["dockerfileAnalysis", "pluginVersion"]),
    );
    expect(factTypes).not.toContain("depGraph");

    const bom = scanResult.facts.find((fact) => fact.type === "sbom")
      ?.data as CycloneDxBom;
    const componentNames = bom.components.map((component) => component.name);
    expect(componentNames).toEqual(
      expect.arrayContaining(["debian:12", "curl", "git"]),
    );

    const baseImageComponent = bom.components.find(
      (component) => component.name === "debian:12",
    );
    expect(baseImageComponent?.type).toBe("container");
  });

  it("rejects with a clear error when neither an image nor a Dockerfile is supplied", async () => {
    await expect(scan({ sbom: true })).rejects.toThrow(SBOM_TARGET_ERROR);

    let caughtError: unknown;
    try {
      await scan({ sbom: true });
    } catch (error) {
      caughtError = error;
    }
    expect(caughtError).toBeInstanceOf(Error);
    expect(caughtError).not.toBeInstanceOf(TypeError);
    expect((caughtError as Error).message).toBe(SBOM_TARGET_ERROR);
  });

  it("still rejects with the existing message when no options are provided at all", async () => {
    await expect(scan({})).rejects.toThrow(
      "No image identifier or path provided",
    );
  });

  it("rejects with an error naming the missing Dockerfile path", async () => {
    const missingPath = path.join(tmpDir, "does-not-exist");

    await expect(scan({ sbom: true, file: missingPath })).rejects.toThrow(
      new RegExp(missingPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  });
});
