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
  });
});
