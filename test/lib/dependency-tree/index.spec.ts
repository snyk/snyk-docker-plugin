import { AnalyzedPackageWithVersion } from "../../../lib/analyzer/types";
import { buildTree } from "../../../lib/dependency-tree";

const targetImage = "snyk/deptree-test@1.0.0";
const targetOS = {
  name: "snykos",
  version: "1",
  prettyName: "SnykOS GNU/Linux 1",
};
const freqDep = {
  Name: `libsut`,
  Version: "1.0",
  Provides: [],
  Deps: {},
  AutoInstalled: true,
  Purl: `pkg:snyk/libsut@1.0`,
};

function buildFreqDepsList(count: number) {
  const depsInfoList: AnalyzedPackageWithVersion[] = [];

  for (let i = 0, l = count; i < l; i = i + 1) {
    depsInfoList.push({
      Name: `libtest-${i + 1}`,
      Version: "1.0",
      Provides: [],
      Deps: { libsut: true },
      AutoInstalled: true,
      Purl: `pkg:snyk/libtest-${i + 1}@1.0`,
    });
  }

  depsInfoList.push(freqDep);

  return depsInfoList;
}

function obj2array(obj) {
  const arr: any[] = [];
  for (const dep in obj) {
    if (obj.hasOwnProperty(dep)) {
      arr.push(obj[dep]);
    }
  }

  return arr;
}

describe("dependency-tree", () => {
  describe("buildTree", () => {
    describe("Linux Package Managers", () => {
      it("should attach frequent deps to parent when threshold is exceeded", () => {
        const fixture = buildFreqDepsList(100);
        const tree = buildTree(targetImage, "deb", fixture, targetOS);
        const res = obj2array(tree.dependencies);
        expect(
          res.filter((dep) => freqDep.Name in dep.dependencies),
        ).toHaveLength(0);
      });
      it("should attach frequent deps to root when threshold is not met", () => {
        const fixture = buildFreqDepsList(50);
        const tree = buildTree(targetImage, "deb", fixture, targetOS);
        const res = obj2array(tree.dependencies);
        expect(
          res.filter((dep) => freqDep.Name in dep.dependencies),
        ).not.toHaveLength(0);
      });
    });

    describe("Non-Linux Package Managers", () => {
      it("should attach frequent deps to meta-common-packages for non-linux pkg managers when threshold is met", () => {
        const fixture = buildFreqDepsList(100);
        const tree = buildTree(targetImage, "snyk", fixture, targetOS);
        expect(tree.dependencies["meta-common-packages"]).toBeTruthy();
      });
    });

    describe("Edge Cases", () => {
      it("should handle packages with no dependencies (null Deps)", () => {
        // Test the missing branch: depInfo.Deps || {}
        const fixture: AnalyzedPackageWithVersion[] = [
          {
            Name: "package-without-deps",
            Version: "1.0",
            Provides: [],
            Deps: null as any, // Deps is null/undefined
            AutoInstalled: false,
            Purl: "pkg:snyk/package-without-deps@1.0",
          },
          {
            Name: "package-with-empty-deps",
            Version: "1.0",
            Provides: [],
            Deps: {}, // Empty deps object
            AutoInstalled: false,
            Purl: "pkg:snyk/package-with-empty-deps@1.0",
          },
        ];
        const tree = buildTree(targetImage, "deb", fixture, targetOS);
        expect(tree.dependencies["package-without-deps"]).toBeTruthy();
        expect(tree.dependencies["package-without-deps"].dependencies).toEqual(
          {},
        );
        expect(tree.dependencies["package-with-empty-deps"]).toBeTruthy();
        expect(
          tree.dependencies["package-with-empty-deps"].dependencies,
        ).toEqual({});
      });

      it("should handle recursive dependencies gracefully", () => {
        // This tests various branches in buildTreeRecursive
        const fixture: AnalyzedPackageWithVersion[] = [
          {
            Name: "package-a",
            Version: "1.0",
            Provides: [],
            Deps: { "package-b": true },
            AutoInstalled: false,
            Purl: "pkg:snyk/package-a@1.0",
          },
          {
            Name: "package-b",
            Version: "1.0",
            Provides: [],
            Deps: { "package-c": true },
            AutoInstalled: false,
            Purl: "pkg:snyk/package-b@1.0",
          },
          {
            Name: "package-c",
            Version: "1.0",
            Provides: [],
            Deps: { "package-a": true }, // Circular dependency
            AutoInstalled: false,
            Purl: "pkg:snyk/package-c@1.0",
          },
        ];
        const tree = buildTree(targetImage, "deb", fixture, targetOS);
        // Should handle circular dependencies without infinite recursion
        expect(tree.dependencies["package-a"]).toBeTruthy();
        expect(
          tree.dependencies["package-a"].dependencies["package-b"],
        ).toBeTruthy();
        expect(
          tree.dependencies["package-a"].dependencies["package-b"].dependencies[
            "package-c"
          ],
        ).toBeTruthy();
        // The circular reference back to package-a should not be included
        expect(
          tree.dependencies["package-a"].dependencies["package-b"].dependencies[
            "package-c"
          ].dependencies,
        ).toEqual({});
      });

      it("should handle packages with Source field", () => {
        // Test the depFullName function with Source field
        const fixture: AnalyzedPackageWithVersion[] = [
          {
            Name: "subpackage",
            Source: "source-package",
            Version: "1.0",
            Provides: [],
            Deps: {},
            AutoInstalled: false,
            Purl: "pkg:snyk/subpackage@1.0",
          },
        ];
        const tree = buildTree(targetImage, "deb", fixture, targetOS);
        // Should use Source/Name format
        expect(tree.dependencies["source-package/subpackage"]).toBeTruthy();
        expect(tree.dependencies["source-package/subpackage"].version).toBe(
          "1.0",
        );
      });
    });
  });
});
