import {
  buildCycloneDxBom,
  CycloneDxBom,
  SbomSource,
} from "../../../lib/sbom/cyclonedx";
import { DepTree } from "../../../lib/types";
import { PLUGIN_VERSION } from "../../../lib/version";

function findProperty(
  component: CycloneDxBom["components"][number],
  name: string,
): string | undefined {
  return component.properties?.find((property) => property.name === name)
    ?.value;
}

function assertWellFormed(bom: CycloneDxBom): void {
  expect(JSON.parse(JSON.stringify(bom))).toStrictEqual(bom);

  expect(bom.bomFormat).toBe("CycloneDX");
  expect(bom.specVersion).toBe("1.6");
  expect(bom.version).toBe(1);
  expect(bom.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  expect(Number.isFinite(Date.parse(bom.metadata.timestamp))).toBe(true);
  expect(bom.metadata.tools[0].name).toBe("snyk-docker-plugin");
  expect(bom.metadata.tools[0].version).toBe(PLUGIN_VERSION);

  const bomRefs = new Set<string>();
  for (const component of bom.components) {
    expect(component.name.length).toBeGreaterThan(0);
    expect(["library", "container"]).toContain(component.type);
    expect(bomRefs.has(component["bom-ref"])).toBe(false);
    bomRefs.add(component["bom-ref"]);
  }
}

function buildDepTree(deps: DepTree["dependencies"]): DepTree {
  return {
    name: "docker-image|image",
    version: "latest",
    packageFormatVersion: "deb:0.0.1",
    targetOS: { name: "debian", prettyName: "Debian", version: "12" },
    dependencies: deps,
  };
}

describe("buildCycloneDxBom", () => {
  it("is well-formed with no sources at all", () => {
    const bom = buildCycloneDxBom({});
    assertWellFormed(bom);
    expect(bom.components).toEqual([]);
  });

  describe("depTree only", () => {
    const source: SbomSource = {
      depTree: buildDepTree({
        openssl: {
          name: "openssl",
          version: "3.0.11-1",
          purl: "pkg:deb/debian/openssl@3.0.11-1",
          dependencies: {},
        },
        "no-purl-pkg": {
          name: "no-purl-pkg",
          version: "1.0.0",
          dependencies: {},
        },
      }),
    };

    it("produces a well-formed BOM", () => {
      assertWellFormed(buildCycloneDxBom(source));
    });

    it("marks every component as sourced from the image", () => {
      const bom = buildCycloneDxBom(source);
      expect(bom.components).toHaveLength(2);
      for (const component of bom.components) {
        expect(findProperty(component, "snyk:sbom:source")).toBe("image");
      }
    });

    it("keeps purl when the depTree node had one, and omits it otherwise", () => {
      const bom = buildCycloneDxBom(source);
      const withPurl = bom.components.find((c) => c.name === "openssl");
      const withoutPurl = bom.components.find((c) => c.name === "no-purl-pkg");

      expect(withPurl?.purl).toBe("pkg:deb/debian/openssl@3.0.11-1");
      expect(withoutPurl).toBeDefined();
      expect(withoutPurl).not.toHaveProperty("purl");
    });
  });

  describe("appComponents only", () => {
    const source: SbomSource = {
      appComponents: [
        {
          name: "lodash",
          version: "4.17.21",
          purl: "pkg:npm/lodash@4.17.21",
          targetFile: "/app/package-lock.json",
        },
        { name: "left-pad", version: "1.3.0" },
      ],
    };

    it("produces a well-formed BOM", () => {
      assertWellFormed(buildCycloneDxBom(source));
    });

    it("marks every component as sourced from the application", () => {
      const bom = buildCycloneDxBom(source);
      expect(bom.components).toHaveLength(2);
      for (const component of bom.components) {
        expect(findProperty(component, "snyk:sbom:source")).toBe("application");
      }
    });

    it("carries the target file only when it was supplied", () => {
      const bom = buildCycloneDxBom(source);
      const withTargetFile = bom.components.find((c) => c.name === "lodash");
      const withoutTargetFile = bom.components.find(
        (c) => c.name === "left-pad",
      );

      expect(findProperty(withTargetFile!, "snyk:sbom:targetFile")).toBe(
        "/app/package-lock.json",
      );
      expect(
        findProperty(withoutTargetFile!, "snyk:sbom:targetFile"),
      ).toBeUndefined();
    });
  });

  describe("dockerfileAnalysis only", () => {
    const source: SbomSource = {
      dockerfileAnalysis: {
        baseImage: "node:18-alpine",
        dockerfilePackages: {
          curl: { instruction: "RUN", installCommand: "apt-get install curl" },
          git: { instruction: "RUN", installCommand: "apt-get install git" },
        },
        dockerfileLayers: {},
      },
    };

    it("produces a well-formed BOM", () => {
      assertWellFormed(buildCycloneDxBom(source));
    });

    it("marks every package component as sourced from the dockerfile", () => {
      const bom = buildCycloneDxBom(source);
      const packageComponents = bom.components.filter(
        (c) => c.name !== "node:18-alpine",
      );
      expect(packageComponents).toHaveLength(2);
      for (const component of packageComponents) {
        expect(findProperty(component, "snyk:sbom:source")).toBe("dockerfile");
      }
    });

    it("includes the base image as a container component", () => {
      const bom = buildCycloneDxBom(source);
      const baseImageComponent = bom.components.find(
        (c) => c.name === "node:18-alpine",
      );
      expect(baseImageComponent).toBeDefined();
      expect(baseImageComponent?.type).toBe("container");
    });
  });

  describe("all three sources together", () => {
    const source: SbomSource = {
      imageName: "node:18-alpine",
      depTree: buildDepTree({
        curl: {
          name: "curl",
          version: "8.4.0-1",
          purl: "pkg:deb/debian/curl@8.4.0-1",
          dependencies: {},
        },
        openssl: {
          name: "openssl",
          version: "3.0.11-1",
          dependencies: {},
        },
      }),
      appComponents: [{ name: "lodash", version: "4.17.21" }],
      dockerfileAnalysis: {
        baseImage: "node:18-alpine",
        dockerfilePackages: {
          // Present in both the image scan and the Dockerfile: should
          // collapse into a single component, not a duplicate.
          curl: { instruction: "RUN", installCommand: "apt-get install curl" },
          git: { instruction: "RUN", installCommand: "apt-get install git" },
        },
        dockerfileLayers: {},
      },
    };

    it("produces a well-formed BOM", () => {
      assertWellFormed(buildCycloneDxBom(source));
    });

    it("yields exactly one document with components from all three sources", () => {
      const bom = buildCycloneDxBom(source);

      const names = bom.components.map((c) => c.name);
      expect(new Set(names).size).toBe(names.length);

      expect(names).toEqual(
        expect.arrayContaining([
          "curl",
          "openssl",
          "lodash",
          "git",
          "node:18-alpine",
        ]),
      );
    });

    it("does not duplicate a name@version present in multiple sources", () => {
      const bom = buildCycloneDxBom(source);
      const curlComponents = bom.components.filter((c) => c.name === "curl");
      expect(curlComponents).toHaveLength(1);
    });

    it("merges the source list for a package found via multiple sources", () => {
      const bom = buildCycloneDxBom(source);
      const curl = bom.components.find((c) => c.name === "curl");
      expect(curl?.version).toBe("8.4.0-1");
      expect(findProperty(curl!, "snyk:sbom:source")).toBe("image,dockerfile");
    });

    it("keeps single-source components correctly attributed", () => {
      const bom = buildCycloneDxBom(source);
      const openssl = bom.components.find((c) => c.name === "openssl");
      const lodash = bom.components.find((c) => c.name === "lodash");
      const git = bom.components.find((c) => c.name === "git");

      expect(findProperty(openssl!, "snyk:sbom:source")).toBe("image");
      expect(findProperty(lodash!, "snyk:sbom:source")).toBe("application");
      expect(findProperty(git!, "snyk:sbom:source")).toBe("dockerfile");
    });
  });
});
