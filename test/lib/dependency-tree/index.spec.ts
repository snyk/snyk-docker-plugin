import { AnalyzedPackageWithVersion } from "../../../lib/analyzer/types";
import {
  buildTree,
  nameAndVersionFromTargetImage,
} from "../../../lib/dependency-tree";

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

const validSha256 =
  "sha256:56ea7092e72db3e9f84d58d583370d59b842de02ea9e1f836c3f3afc7ce408c1";

describe("nameAndVersionFromTargetImage", () => {
  describe("handles valid image references", () => {
    it("with repository only", () => {
      expect(nameAndVersionFromTargetImage("nginx")).toEqual({
        name: "nginx",
        version: "latest",
      });
    });

    it("with tag", () => {
      expect(nameAndVersionFromTargetImage("nginx:1.23")).toEqual({
        name: "nginx",
        version: "1.23",
      });
    });

    it("with digest", () => {
      expect(nameAndVersionFromTargetImage(`nginx@${validSha256}`)).toEqual({
        name: "nginx",
        version: "",
      });
    });

    it("with tag and digest", () => {
      expect(
        nameAndVersionFromTargetImage(`nginx:1.23@${validSha256}`),
      ).toEqual({
        name: "nginx",
        version: "1.23",
      });
    });

    it("with registry", () => {
      expect(nameAndVersionFromTargetImage("gcr.io/project/nginx")).toEqual({
        name: "gcr.io/project/nginx",
        version: "latest",
      });
    });

    it("with registry and port", () => {
      expect(nameAndVersionFromTargetImage("localhost:5000/foo/bar")).toEqual({
        name: "localhost:5000/foo/bar",
        version: "latest",
      });
    });

    it("with registry and port and tag", () => {
      expect(
        nameAndVersionFromTargetImage("localhost:5000/foo/bar:tag"),
      ).toEqual({
        name: "localhost:5000/foo/bar",
        version: "tag",
      });
    });

    it("with registry and port and digest", () => {
      expect(
        nameAndVersionFromTargetImage(`localhost:5000/foo/bar@${validSha256}`),
      ).toEqual({
        name: "localhost:5000/foo/bar",
        version: "",
      });
    });

    it("with registry, port, digest and tag", () => {
      expect(
        nameAndVersionFromTargetImage(
          `localhost:5000/foo/bar:tag@${validSha256}`,
        ),
      ).toEqual({
        name: "localhost:5000/foo/bar",
        version: "tag",
      });
    });

    it("with library/ namespace", () => {
      expect(nameAndVersionFromTargetImage("library/nginx:latest")).toEqual({
        name: "library/nginx",
        version: "latest",
      });
    });

    it("with dots and dashes in the tag", () => {
      expect(nameAndVersionFromTargetImage("nginx:1.23.0-alpha")).toEqual({
        name: "nginx",
        version: "1.23.0-alpha",
      });
    });
  });

  // These tests are to verify that the previous logic is still working as expected for
  // references that cannot be parsed by the new parseImageReference function.
  // They are not necessarily asserting that this is the correct parsing logic.
  describe("handles file-based reference strings", () => {
    it("with a simple image name", () => {
      expect(nameAndVersionFromTargetImage("image.tar")).toEqual({
        name: "image.tar",
        version: "",
      });
    });

    it("with a longer path", () => {
      expect(nameAndVersionFromTargetImage("path/to/archive.tar")).toEqual({
        name: "path/to/archive.tar",
        version: "",
      });
    });

    it("with a tag", () => {
      expect(nameAndVersionFromTargetImage("path/to/archive.tar:tag")).toEqual({
        name: "path/to/archive.tar",
        version: "tag",
      });
    });

    it("with a digest", () => {
      expect(
        nameAndVersionFromTargetImage(`archive.tar@${validSha256}`),
      ).toEqual({
        name: "archive.tar",
        version: "",
      });
    });

    it("with a tag and digest", () => {
      expect(
        nameAndVersionFromTargetImage(`path/to/archive.tar:tag@${validSha256}`),
      ).toEqual({
        name: "path/to/archive.tar",
        version: "tag",
      });
    });

    it("with a tag and specific image name", () => {
      expect(
        nameAndVersionFromTargetImage("path/to/archive.tar:image:tag"),
      ).toEqual({
        name: "path/to/archive.tar:image",
        version: "tag",
      });
    });

    it("with a tag and specific image name and digest", () => {
      expect(
        nameAndVersionFromTargetImage(
          `path/to/archive.tar:image:tag@${validSha256}`,
        ),
      ).toEqual({
        name: "path/to/archive.tar:image:tag",
        version: "",
      });
    });
  });
});
