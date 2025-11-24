import * as elf from "elfy";
import * as fs from "fs";
import * as path from "path";

import { extractContent, scan } from "../../../lib";
import { getGoModulesContentAction } from "../../../lib/go-parser";
import { GoBinary } from "../../../lib/go-parser/go-binary";
import { getFixture } from "../../util";

describe("gomodules binaries scanning", () => {
  afterAll(() => {
    jest.resetAllMocks();
  });

  it("should return expected result", async () => {
    // Arrange
    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    // Act
    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    // Assert
    expect(pluginResult).toMatchSnapshot();
  });

  it("should extract image content successfully", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.17.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;
    const result = await extractContent([getGoModulesContentAction], {
      path: imageNameAndTag,
    });
    const testgoBinary = result.extractedLayers["/testgo"];
    expect(testgoBinary).toBeTruthy();
    expect("gomodules" in testgoBinary).toBeTruthy();
  });

  it("return plugin result when Go binary cannot be parsed do not break layer iterator", async () => {
    const elfParseMock = jest.spyOn(elf, "parse").mockImplementation(() => {
      throw new Error("Cannot read property 'type' of undefined");
    });

    const fixturePath = getFixture("docker-archives/docker-save/yq.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });
    expect(pluginResult).toMatchSnapshot();
    elfParseMock.mockRestore();
  });
});

describe("parse go modules from various versions of compiled binaries", () => {
  it("go 1.17", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.17.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("go 1.18", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.18.3.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("go 1.19", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/testgo-1.19rc1.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});

/**
 * Unit Tests: Stripped/CGo Binary Support
 *
 * Tests GoBinary class directly with a stripped binary fixture (no .gopclntab section).
 * Validates module-level dependency extraction from .go.buildinfo.
 *
 * Fixture: test/fixtures/go-binaries/no-pcln-tab
 * - Source: github.com/rootless-containers/rootlesskit/cmd/rootlesskit-docker-proxy
 * - Go Version: 1.17.11
 * - Dependencies: 3 modules
 * - Expected output verified with: go version -m test/fixtures/go-binaries/no-pcln-tab
 */
describe("Stripped Go binary without .gopclntab: no-pcln-tab fixture", () => {
  const fixturesPath = path.join(__dirname, "../../fixtures/go-binaries");
  const noPclnTabPath = path.join(fixturesPath, "no-pcln-tab");

  // Expected dependencies for no-pcln-tab fixture based on `go version -m`
  const expectedDepsNoPcln = [
    { name: "github.com/pkg/errors", version: "v0.9.1" },
    { name: "github.com/sirupsen/logrus", version: "v1.8.1" },
    { name: "golang.org/x/sys", version: "v0.0.0-20210119212857-b64e53b001e4" },
  ];

  it("should have .go.buildinfo but no .gopclntab", () => {
    const fileContent = fs.readFileSync(noPclnTabPath);
    const binary = elf.parse(fileContent);

    const goBuildInfo = binary.body.sections.find(
      (section) => section.name === ".go.buildinfo",
    );
    const goPclnTab = binary.body.sections.find(
      (section) => section.name === ".gopclntab",
    );

    expect(goBuildInfo).toBeDefined();
    expect(goPclnTab).toBeUndefined();
  });

  it("should extract 3 module-level dependencies from .go.buildinfo", async () => {
    const fileContent = fs.readFileSync(noPclnTabPath);
    const binary = elf.parse(fileContent);

    const goBinary = new GoBinary(binary);
    const depGraph = await goBinary.depGraph();

    const deps = depGraph
      .getPkgs()
      .filter((pkg) => pkg.name !== depGraph.rootPkg.name);

    expectedDepsNoPcln.forEach((expectedDep) => {
      const found = deps.find(
        (dep) =>
          dep.name === expectedDep.name && dep.version === expectedDep.version,
      );
      expect(found).toBeDefined();
    });

    expect(deps.length).toBe(expectedDepsNoPcln.length);
    expect(depGraph.rootPkg.name).toBe(
      "github.com/rootless-containers/rootlesskit",
    );
  });

  it("should report module-level dependencies (not package-level)", async () => {
    const fileContent = fs.readFileSync(noPclnTabPath);
    const binary = elf.parse(fileContent);

    const goBinary = new GoBinary(binary);

    const hasPackageLevelInfo = goBinary.modules.some(
      (mod) => mod.packages.length > 0,
    );

    expect(hasPackageLevelInfo).toBe(false);
    expect(goBinary.modules.length).toBe(3);
  });
});

/**
 * Test Image: test/fixtures/docker-archives/stripped-go-binaries-minimal.tar.gz
 * - Size: 18 MB compressed, 62 MB uncompressed
 * - Source: elastic-agent-complete:8.18.8
 * - Binaries: 2 stripped Go binaries
 *   1. fleet-server (76 modules)
 *   2. osquery-extension.ext (10 modules) - we currently filter out binaries with extensions TODO-fix this
 */
describe("Stripped and CGo Go binaries detection scan handler test", () => {
  const testImagePath = getFixture(
    "docker-archives/stripped-go-binaries-minimal.tar.gz",
  );
  jest.setTimeout(180000);
  const getScanOptions = () => {
    return {
      path: `docker-archive:${testImagePath}`,
      "app-vulns": true,
    };
  };

  it("should detect stripped/CGo Go binaries missing .gopclntab section", async () => {
    const pluginResult = await scan(getScanOptions());

    const goModules = pluginResult.scanResults.filter(
      (r) => r.identity.type === "gomodules",
    );

    expect(goModules.length).toBeGreaterThanOrEqual(1);

    const detectedBinaries: {
      fleetServer: { targetFile: string; moduleCount: number } | null;
      osqueryExt: { targetFile: string; moduleCount: number } | null;
    } = {
      fleetServer: null,
      osqueryExt: null,
    };

    goModules.forEach((result) => {
      const targetFile = result.identity.targetFile || "";
      const depGraphFact = result.facts.find((f) => f.type === "depGraph");
      const depGraph = depGraphFact?.data;

      if (!depGraph) {
        return;
      }

      const packages = depGraph.getPkgs();
      const moduleCount = packages.length;

      if (targetFile.includes("fleet-server")) {
        detectedBinaries.fleetServer = { targetFile, moduleCount };
      }
    });

    if (detectedBinaries.fleetServer) {
      expect(detectedBinaries.fleetServer.moduleCount).toEqual(76);
    } else {
      fail("fleet-server not detected");
    }

    const detectedCount =
      Object.values(detectedBinaries).filter(Boolean).length;
    expect(detectedCount).toBe(1);
  });

  it("should report module-level dependencies (not package-level) for stripped/CGo binaries", async () => {
    const pluginResult = await scan(getScanOptions());

    const goModules = pluginResult.scanResults.filter(
      (r) => r.identity.type === "gomodules",
    );

    expect(goModules.length).toEqual(1);

    const fleetServer = goModules.find((r) =>
      r.identity.targetFile?.includes("fleet-server"),
    );

    if (!fleetServer) {
      return;
    }

    const depGraphFact = fleetServer.facts.find((f) => f.type === "depGraph");
    const depGraph = depGraphFact?.data;

    expect(depGraph).toBeDefined();

    const packages = depGraph.getPkgs();
    const sampleDeps = packages.slice(0, 10);

    sampleDeps.forEach((pkg: any) => {
      expect(pkg.name).toBeDefined();
      if (pkg.version !== undefined) {
        expect(typeof pkg.version).toBe("string");
      }
    });
  });
});
