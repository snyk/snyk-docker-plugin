import { readFileSync } from "fs";
import { join } from "path";
import {
  parsePackagesConfig,
  parseProjectFile,
  parsePackagesLockJson,
  parseProjectAssetsJson,
} from "../../lib/dotnet-parser";

const fixturesRoot = join(__dirname, "../fixtures/dotnet");

function readFixture(relativePath: string): string {
  return readFileSync(join(fixturesRoot, relativePath), "utf8");
}

function packageNamesAndVersions(
  packages: { name: string; version: string }[],
): { name: string; version: string }[] {
  return packages.map(({ name, version }) => ({ name, version }));
}

describe("dotnet parsers", () => {
  describe("parsePackagesConfig", () => {
    it("returns exact package names and versions from the fixture", () => {
      const content = readFixture("packages.config");

      const packages = parsePackagesConfig(content);

      expect(packageNamesAndVersions(packages)).toEqual([
        { name: "AutoMapper", version: "13.0.1" },
        { name: "Newtonsoft.Json", version: "13.0.3" },
      ]);
    });

    it('excludes packages with developmentDependency="true"', () => {
      const content = readFixture("packages.config");

      const packages = parsePackagesConfig(content);

      expect(packages).not.toEqual(
        expect.arrayContaining([{ name: "DevOnly", version: "1.0.0" }]),
      );
    });

    it("returns an empty list for malformed or truncated content instead of throwing", () => {
      expect(() => parsePackagesConfig("<packages><package id=")).not.toThrow();
      expect(parsePackagesConfig("<packages><package id=")).toEqual([]);

      expect(() => parsePackagesConfig("")).not.toThrow();
      expect(parsePackagesConfig("")).toEqual([]);
    });
  });

  describe("parseProjectFile", () => {
    it("returns exact package names and versions from the fixture", () => {
      const content = readFixture("VulnApp.csproj");

      const packages = parseProjectFile(content);

      expect(packageNamesAndVersions(packages)).toEqual([
        { name: "AutoMapper", version: "13.0.1" },
        { name: "ExactSibling", version: "1.0.0" },
        { name: "ChildElementRef", version: "3.0.0" },
      ]);
    });

    it("excludes PackageReference entries inside XML comments", () => {
      const content = readFixture("VulnApp.csproj");

      const packages = parseProjectFile(content);

      expect(packages).not.toEqual(
        expect.arrayContaining([{ name: "CommentedOut", version: "9.9.9" }]),
      );
    });

    it("skips PackageReference versions that are MSBuild properties, wildcards, or ranges", () => {
      const content = readFixture("VulnApp.csproj");

      const packages = parseProjectFile(content);

      expect(packages).not.toEqual(
        expect.arrayContaining([
          { name: "PropRef", version: "$(SomeProperty)" },
          { name: "WildcardRef", version: "1.2.*" },
          { name: "RangeRef", version: "[1.0,2.0)" },
        ]),
      );
      expect(packages).toEqual(
        expect.arrayContaining([{ name: "ExactSibling", version: "1.0.0" }]),
      );
    });

    it("excludes PackageReference entries using Update= instead of Include=", () => {
      const content = readFixture("VulnApp.csproj");

      const packages = parseProjectFile(content);

      expect(packages).not.toEqual(
        expect.arrayContaining([{ name: "UpdateRef", version: "2.0.0" }]),
      );
    });

    it("parses the child-element <Version> form", () => {
      const content = readFixture("VulnApp.csproj");

      const packages = parseProjectFile(content);

      expect(packages).toEqual(
        expect.arrayContaining([{ name: "ChildElementRef", version: "3.0.0" }]),
      );
    });

    it("returns an empty list for malformed or truncated content instead of throwing", () => {
      expect(() =>
        parseProjectFile("<Project><PackageReference Include="),
      ).not.toThrow();
      expect(parseProjectFile("<Project><PackageReference Include=")).toEqual(
        [],
      );

      expect(() => parseProjectFile("")).not.toThrow();
      expect(parseProjectFile("")).toEqual([]);
    });
  });

  describe("parsePackagesLockJson", () => {
    it("returns exact package names and versions from the fixture", () => {
      const content = readFixture("packages.lock.json");

      const result = parsePackagesLockJson(content);

      expect(result).not.toBeNull();
      expect(packageNamesAndVersions(result!.packages)).toEqual(
        expect.arrayContaining([
          { name: "AutoMapper", version: "13.0.1" },
          { name: "Microsoft.Extensions.Options", version: "6.0.0" },
          {
            name: "Microsoft.Extensions.DependencyInjection.Abstractions",
            version: "6.0.0",
          },
        ]),
      );
      expect(result!.packages).toHaveLength(3);
    });

    it("traverses Project-type entries for dependencies but does not emit them as packages", () => {
      const content = readFixture("packages.lock.json");

      const result = parsePackagesLockJson(content);

      expect(result).not.toBeNull();
      expect(result!.rootName).toBe("VulnApp");
      expect(result!.packages).not.toEqual(
        expect.arrayContaining([
          { name: "VulnApp", version: expect.any(String) },
        ]),
      );
      expect(result!.directDependencies).toEqual(
        expect.arrayContaining(["AutoMapper"]),
      );
    });

    it("returns null for malformed or truncated content instead of throwing", () => {
      expect(() => parsePackagesLockJson("{")).not.toThrow();
      expect(parsePackagesLockJson("{")).toBeNull();

      expect(() => parsePackagesLockJson("not json")).not.toThrow();
      expect(parsePackagesLockJson("not json")).toBeNull();

      expect(() => parsePackagesLockJson("")).not.toThrow();
      expect(parsePackagesLockJson("")).toBeNull();
    });
  });

  describe("parseProjectAssetsJson", () => {
    it("returns exact package names and versions from the fixture", () => {
      const content = readFixture("project.assets.json");

      const result = parseProjectAssetsJson(content);

      expect(result).not.toBeNull();
      expect(packageNamesAndVersions(result!.packages)).toEqual(
        expect.arrayContaining([
          { name: "AutoMapper", version: "13.0.1" },
          { name: "Microsoft.Extensions.Options", version: "6.0.0" },
          {
            name: "Microsoft.Extensions.DependencyInjection.Abstractions",
            version: "6.0.0",
          },
        ]),
      );
      expect(result!.packages).toHaveLength(3);
    });

    it("traverses project-type libraries but does not emit them as packages", () => {
      const content = readFixture("project.assets.json");

      const result = parseProjectAssetsJson(content);

      expect(result).not.toBeNull();
      expect(result!.rootName).toBe("VulnApp");
      expect(result!.packages).not.toEqual(
        expect.arrayContaining([{ name: "VulnApp", version: "1.0.0" }]),
      );
      expect(result!.directDependencies).toEqual(
        expect.arrayContaining(["AutoMapper"]),
      );
    });

    it("returns null for malformed or truncated content instead of throwing", () => {
      expect(() => parseProjectAssetsJson("{")).not.toThrow();
      expect(parseProjectAssetsJson("{")).toBeNull();

      expect(() => parseProjectAssetsJson("not json")).not.toThrow();
      expect(parseProjectAssetsJson("not json")).toBeNull();

      expect(() => parseProjectAssetsJson("")).not.toThrow();
      expect(parseProjectAssetsJson("")).toBeNull();
    });
  });
});
