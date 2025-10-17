import { execSync } from "child_process";
import * as elf from "elfy";
import * as fs from "fs";
import * as path from "path";
import { GoBinary } from "../../../lib/go-parser/go-binary";

/**
 * Stripped Go Binary Test
 *
 * This test validates Go binary scanning for binaries that lack .gopclntab section
 * but have .go.buildinfo, which is common for stripped binaries and CGo builds.
 *
 * Binary Source:
 *   Binary: cloudbeat (Elastic Agent component)
 *   Image: docker.elastic.co/elastic-agent/elastic-agent-complete:8.18.8
 *   Path: /usr/share/elastic-agent/data/elastic-agent-bb58d0/components/cloudbeat
 *
 * Extraction Steps:
 *   1. docker create --name temp-elastic docker.elastic.co/elastic-agent/elastic-agent-complete:8.18.8
 *   2. docker cp temp-elastic:/usr/share/elastic-agent/data/elastic-agent-bb58d0/components/cloudbeat test/fixtures/go-binaries/cloudbeat
 *   3. gzip cloudbeat  (to create cloudbeat.gz)
 *   4. docker rm temp-elastic
 *
 * Binary Characteristics:
 *   - Size: ~362MB uncompressed (stored as cloudbeat.gz - 78MB compressed)
 *   - Go Version: 1.24.0
 *   - Has .go.buildinfo: Yes
 *   - Has .gopclntab: No (stripped)
 *   - Total dependencies: 502
 *   - Note: Binary is automatically decompressed before tests and cleaned up after
 *
 * Validation:
 *   The expected dependency count (502) was verified using `go version -m`:
 *     $ go version -m test/fixtures/go-binaries/cloudbeat | grep "^	dep" | wc -l
 *     502
 *
 *   This confirms our scanner extracts the same dependencies that Go's built-in
 *   tooling reports, validating the .go.buildinfo parsing is correct.
 *
 * Repository Storage:
 *   Only cloudbeat.gz is committed to reduce repository size.
 *   The uncompressed binary is created during test execution and removed after.
 */
describe("Stripped Go binary without .gopclntab", () => {
  const fixturesPath = path.join(__dirname, "../../fixtures/go-binaries");
  const cloudbeatPath = path.join(fixturesPath, "cloudbeat");
  const cloudbeatGzPath = path.join(fixturesPath, "cloudbeat.gz");

  // Decompress cloudbeat.gz before tests (78MB compressed -> 362MB uncompressed)
  beforeAll(() => {
    if (!fs.existsSync(cloudbeatGzPath)) {
      throw new Error(
        `Cloudbeat compressed fixture not found at ${cloudbeatGzPath}. ` +
          `Please extract it from the Elastic Agent image and compress it.`,
      );
    }
    // Always decompress for tests
    execSync(`gunzip -k "${cloudbeatGzPath}"`, { cwd: fixturesPath });
  });

  // Clean up decompressed binary after tests (keep only .gz in repo)
  afterAll(() => {
    if (fs.existsSync(cloudbeatPath)) {
      fs.unlinkSync(cloudbeatPath);
    }
  });

  // Expected dependencies based on `go version -m cloudbeat`
  // Total: 502 dependencies
  const expectedSampleDeps = [
    { name: "cel.dev/expr", version: "v0.19.1" },
    { name: "cloud.google.com/go", version: "v0.118.0" },
    { name: "cloud.google.com/go/accesscontextmanager", version: "v1.9.3" },
    { name: "cloud.google.com/go/asset", version: "v1.20.4" },
    { name: "cloud.google.com/go/auth", version: "v0.14.0" },
    { name: "cloud.google.com/go/storage", version: "v1.49.0" },
    {
      name: "github.com/Azure/azure-sdk-for-go",
      version: "v68.0.0+incompatible",
    },
    {
      name: "github.com/Azure/azure-sdk-for-go/sdk/azcore",
      version: "v1.17.0",
    },
    {
      name: "github.com/Azure/azure-sdk-for-go/sdk/azidentity",
      version: "v1.8.1",
    },
    { name: "github.com/aws/aws-sdk-go-v2", version: "v1.34.0" },
    { name: "github.com/aws/aws-sdk-go-v2/config", version: "v1.29.2" },
    { name: "github.com/elastic/elastic-agent-libs", version: "v0.18.1" },
    { name: "golang.org/x/crypto", version: "v0.36.0" },
    { name: "golang.org/x/net", version: "v0.38.0" },
    { name: "golang.org/x/sys", version: "v0.31.0" },
    { name: "google.golang.org/api", version: "v0.218.0" },
    { name: "google.golang.org/grpc", version: "v1.71.1" },
    { name: "google.golang.org/protobuf", version: "v1.36.6" },
  ];

  beforeAll(() => {
    // Verify fixture exists
    if (!fs.existsSync(cloudbeatPath)) {
      throw new Error(
        `Cloudbeat fixture not found at ${cloudbeatPath}. ` +
          `Please extract it from the Elastic Agent image first.`,
      );
    }
  });

  it("should have .go.buildinfo but no .gopclntab (stripped binary)", () => {
    const fileContent = fs.readFileSync(cloudbeatPath);
    const binary = elf.parse(fileContent);

    const goBuildInfo = binary.body.sections.find(
      (section) => section.name === ".go.buildinfo",
    );
    const goBuildId = binary.body.sections.find(
      (section) => section.name === ".note.go.buildid",
    );
    const goPclnTab = binary.body.sections.find(
      (section) => section.name === ".gopclntab",
    );

    expect(goBuildInfo).toBeDefined();
    expect(goBuildId).toBeDefined();
    expect(goPclnTab).toBeUndefined(); // Stripped binary - no pclntab
  });

  it("should extract 502 dependencies from .go.buildinfo", async () => {
    const fileContent = fs.readFileSync(cloudbeatPath);
    const binary = elf.parse(fileContent);

    const goBinary = new GoBinary(binary as any);
    const depGraph = await goBinary.depGraph();

    const deps = depGraph
      .getPkgs()
      .filter((pkg) => pkg.name !== depGraph.rootPkg.name);

    // go version -m reports 502 dependencies
    expect(deps.length).toBe(502);

    // Validate root package
    expect(depGraph.rootPkg.name).toBe("github.com/elastic/cloudbeat");
  });

  it("should extract correct dependency names and versions", async () => {
    const fileContent = fs.readFileSync(cloudbeatPath);
    const binary = elf.parse(fileContent);

    const goBinary = new GoBinary(binary as any);
    const depGraph = await goBinary.depGraph();

    const deps = depGraph
      .getPkgs()
      .filter((pkg) => pkg.name !== depGraph.rootPkg.name);

    // Validate each expected dependency is present with correct version
    expectedSampleDeps.forEach((expectedDep) => {
      const found = deps.find(
        (dep) =>
          dep.name === expectedDep.name && dep.version === expectedDep.version,
      );
      expect(found).toBeDefined();
    });
  });

  it("should report module-level dependencies (not package-level)", async () => {
    const fileContent = fs.readFileSync(cloudbeatPath);
    const binary = elf.parse(fileContent);

    const goBinary = new GoBinary(binary as any);

    // Check that modules have no packages (because pclntab is missing)
    const hasPackageLevelInfo = goBinary.modules.some(
      (mod) => mod.packages.length > 0,
    );

    // Without .gopclntab, we should only have module-level info
    expect(hasPackageLevelInfo).toBe(false);
    expect(goBinary.modules.length).toBe(502);
  });

  it("should validate cloud provider dependencies are present", async () => {
    const fileContent = fs.readFileSync(cloudbeatPath);
    const binary = elf.parse(fileContent);

    const goBinary = new GoBinary(binary as any);
    const depGraph = await goBinary.depGraph();

    const deps = depGraph
      .getPkgs()
      .filter((pkg) => pkg.name !== depGraph.rootPkg.name);

    // Check for major cloud providers (cloudbeat monitors AWS, Azure, GCP)
    const awsDeps = deps.filter((dep) =>
      dep.name.includes("github.com/aws/aws-sdk-go"),
    );
    const azureDeps = deps.filter((dep) =>
      dep.name.includes("github.com/Azure/azure-sdk-for-go"),
    );
    const gcpDeps = deps.filter((dep) =>
      dep.name.includes("cloud.google.com/go"),
    );

    expect(awsDeps.length).toBe(37);
    expect(azureDeps.length).toBe(16);
    expect(gcpDeps.length).toBe(12);
  });
});

/**
 * Test fixture binary: no-pcln-tab (from test/fixtures/go-binaries)
 *
 * This is a smaller test fixture specifically created without .gopclntab section.
 *
 * Binary Source:
 *   Path: github.com/rootless-containers/rootlesskit/cmd/rootlesskit-docker-proxy
 *   Go Version: 1.17.11
 *
 * Expected Dependencies Validation:
 *   The expected dependency list was verified using `go version -m`:
 *     $ go version -m test/fixtures/go-binaries/no-pcln-tab
 *     no-pcln-tab: go1.17.11
 *       path	github.com/rootless-containers/rootlesskit/cmd/rootlesskit-docker-proxy
 *       mod	github.com/rootless-containers/rootlesskit	v0.14.4
 *       dep	github.com/pkg/errors	v0.9.1
 *       dep	github.com/sirupsen/logrus	v1.8.1
 *       dep	golang.org/x/sys	v0.0.0-20210119212857-b64e53b001e4
 *
 *   Total dependencies: 3
 */
describe("Stripped Go binary: no-pcln-tab fixture", () => {
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

    const goBinary = new GoBinary(binary as any);
    const depGraph = await goBinary.depGraph();

    const deps = depGraph
      .getPkgs()
      .filter((pkg) => pkg.name !== depGraph.rootPkg.name);

    // Validate expected dependencies are present with correct versions
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

    const goBinary = new GoBinary(binary as any);

    // Check that modules have no packages (because pclntab is missing)
    const hasPackageLevelInfo = goBinary.modules.some(
      (mod) => mod.packages.length > 0,
    );

    // Without .gopclntab, we should only have module-level info
    expect(hasPackageLevelInfo).toBe(false);
    expect(goBinary.modules.length).toBe(3);
  });
});
