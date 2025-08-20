import { createFromJSON } from "@snyk/dep-graph";
import { readdirSync, readFileSync } from "fs";
import * as path from "path";
import { pipFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { FilePathToContent } from "../../../lib/analyzer/applications/types";
import { getFixture, getObjFromFixture } from "../../util";

function prepareFiles(testPath: string): FilePathToContent {
  const basePath = getFixture(`/python/${testPath}`);
  const filePathToContent = {
    "/app/requirements.txt": readFileSync(
      path.join(basePath, "requirements.txt"),
    ).toString(),
  };
  const sitePackages = readdirSync(path.join(basePath, "site-packages"), {
    withFileTypes: true,
  });
  for (const packageEntity of sitePackages) {
    if (packageEntity.isDirectory()) {
      filePathToContent[
        `/usr/local/lib/python3.10/site-packages/${packageEntity.name}/METADATA`
      ] = readFileSync(
        path.join(basePath, `site-packages/${packageEntity.name}/METADATA`),
      ).toString();
    }
  }
  return filePathToContent;
}

describe("pip analyzer", () => {
  it("correctly creates a dep graph from a requirements file and metadata", async () => {
    const filePathToContent = prepareFiles("ok");
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res[0].identity).toMatchObject({
      type: "pip",
      targetFile: "/app/requirements.txt",
    });
    expect(res[0].facts[0].data._depPkgsList).toHaveLength(8);
  });

  it("correctly creates a dep graph from a requirements using extras", async () => {
    const filePathToContent = prepareFiles("extras");
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res[0].identity).toMatchObject({
      type: "pip",
      targetFile: "/app/requirements.txt",
    });
    const json = getObjFromFixture("python/extras/expected-dep-graph.json");
    const expected = createFromJSON(json);
    // uncomment below to see the diff
    // expect(JSON.stringify(res[0].facts[0].data.toJSON(), null, 2)).toBe(
    //   JSON.stringify(expected.toJSON(), null, 2),
    // );
    expect(res[0].facts[0].data.equals(expected, { compareRoot: false })).toBe(
      true,
    );
  });

  it("correctly creates a dep graph when metadata files are in a different location", async () => {
    const basePath = getFixture(`/python/ok`);
    const filePathToContent = {
      "/app/requirements.txt": readFileSync(
        path.join(basePath, "requirements.txt"),
      ).toString(),
    };
    const sitePackages = readdirSync(path.join(basePath, "site-packages"), {
      withFileTypes: true,
    });
    for (const packageEntity of sitePackages) {
      if (packageEntity.isDirectory()) {
        filePathToContent[
          `/usr/lib/python2.7/site-packages/${packageEntity.name}/METADATA`
        ] = readFileSync(
          path.join(basePath, `site-packages/${packageEntity.name}/METADATA`),
        ).toString();
      }
    }
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res[0].identity).toMatchObject({
      type: "pip",
      targetFile: "/app/requirements.txt",
    });
    expect(res[0].facts[0].data._depPkgsList).toHaveLength(8);
  });

  it("correctly creates a dep graph from a requirements file and missing metadata", async () => {
    const filePathToContent = prepareFiles("missing-deps");
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res[0].identity).toMatchObject({
      type: "pip",
      targetFile: "/app/requirements.txt",
    });
    expect(res[0].facts[0].data._depPkgsList).toHaveLength(5);
  });

  it("uses the correct versions when multiple metadata files are available", async () => {
    const filePathToContent = prepareFiles("two-versions");
    const res = await pipFilesToScannedProjects(filePathToContent);
    const packageList = res[0].facts[0].data._depPkgsList;
    expect(packageList.find((p) => p.name === "flask").version).toEqual(
      "2.2.1",
    );
    expect(packageList.find((p) => p.name === "six").version).toEqual("1.17.0");
    expect(packageList.find((p) => p.name === "rpc.py").version).toEqual(
      "0.4.2",
    );
  });

  it("uses the correct versions when versions are not semver compatible", async () => {
    const filePathToContent = prepareFiles("non-semver-versions");
    const res = await pipFilesToScannedProjects(filePathToContent);
    const packageList = res[0].facts[0].data._depPkgsList;
    expect(packageList.find((p) => p.name === "flask").version).toEqual(
      "2.2.1",
    );
    expect(packageList.find((p) => p.name === "six").version).toEqual("1.17.0");
    expect(packageList.find((p) => p.name === "rpc.py").version).toEqual(
      "0.4.2",
    );
    expect(packageList.find((p) => p.name === "other.py").version).toEqual(
      "7.4.2.15",
    );
  });

  it("uses the latest versions when no version info is available", async () => {
    const filePathToContent = prepareFiles("no-versions");
    const res = await pipFilesToScannedProjects(filePathToContent);
    const packageList = res[0].facts[0].data._depPkgsList;
    expect(packageList.find((p) => p.name === "flask").version).toEqual(
      "2.2.1",
    );
    expect(packageList.find((p) => p.name === "six").version).toEqual("1.17.0");
    expect(packageList.find((p) => p.name === "rpc.py").version).toEqual(
      "0.4.3",
    );
    expect(packageList.find((p) => p.name === "itsdangerous").version).toEqual(
      "2.4.3",
    );
  });

  it("handles cyclic dependencies", async () => {
    const filePathToContent = prepareFiles("cyclic");
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res[0].identity).toMatchObject({
      type: "pip",
      targetFile: "/app/requirements.txt",
    });
    expect(res[0].facts[0].data).toMatchSnapshot();
  });

  it("handles requirements without extras gracefully", async () => {
    // Test when req.extras is undefined
    const filePathToContent = {
      "/app/requirements.txt": "flask==2.2.1\nsix",
      "/usr/local/lib/python3.10/site-packages/flask/METADATA": `Name: flask
Version: 2.2.1
Requires-Dist: six`,
      "/usr/local/lib/python3.10/site-packages/six/METADATA": `Name: six
Version: 1.16.0`,
    };
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res[0].facts[0].data._depPkgsList).toHaveLength(2);
    const flaskNode = res[0].facts[0].data._depPkgsList.find(
      (p) => p.name === "flask",
    );
    expect(flaskNode).toBeDefined();
    expect(flaskNode.version).toEqual("2.2.1");
  });

  it("handles invalid METADATA files gracefully", async () => {
    // Test error handling in getPackageInfo
    const filePathToContent = {
      "/app/requirements.txt": "flask==2.2.1",
      "/usr/local/lib/python3.10/site-packages/flask/METADATA": `Name: flask
Version: 2.2.1`,
      "/usr/local/lib/python3.10/site-packages/invalid/METADATA": `Invalid METADATA content
This will cause getPackageInfo to throw`,
    };
    // Should not throw, just skip the invalid file
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res[0]).toBeDefined();
    expect(res[0].facts[0].data._depPkgsList).toHaveLength(1);
  });

  it("returns empty array when no metadata files are found", async () => {
    const filePathToContent = {
      "/app/requirements.txt": "flask==2.2.1\nsix",
    };
    const res = await pipFilesToScannedProjects(filePathToContent);
    expect(res).toHaveLength(0);
  });

  it("skips empty requirements files", async () => {
    // Test the missing branch: requirements[requirementsFile].length === 0
    const filePathToContent = {
      "/app/requirements.txt": "", // Empty requirements file
      "/other/requirements.txt": "six==1.16.0",
      "/usr/local/lib/python3.10/site-packages/six/METADATA": `Name: six
Version: 1.16.0`,
    };
    const res = await pipFilesToScannedProjects(filePathToContent);
    // Should only process the non-empty requirements file
    expect(res).toHaveLength(1);
    expect(res[0].identity.targetFile).toBe("/other/requirements.txt");
  });

  it("processes files even when packages have no metadata", async () => {
    // The builder.build() method always returns a DepGraph, never null
    // So this test verifies that files with missing metadata are still processed
    const filePathToContent = {
      "/app/requirements.txt": "nonexistent-package==1.0.0",
      "/other/requirements.txt": "six==1.16.0",
      "/usr/local/lib/python3.10/site-packages/six/METADATA": `Name: six
Version: 1.16.0`,
    };
    const res = await pipFilesToScannedProjects(filePathToContent);
    // Both files should be processed
    expect(res).toHaveLength(2);
    // Find the results by targetFile
    const badResult = res.find(
      (r) => r.identity.targetFile === "/app/requirements.txt",
    );
    const goodResult = res.find(
      (r) => r.identity.targetFile === "/other/requirements.txt",
    );

    expect(badResult).toBeDefined();
    expect(goodResult).toBeDefined();

    // The file with nonexistent package should have a dep graph with just the root
    expect(badResult.facts[0].data._depPkgsList).toHaveLength(0);
    // The file with six should have the package
    expect(goodResult.facts[0].data._depPkgsList).toHaveLength(1);
  });
});
