import { readdirSync, readFileSync } from "fs";
import * as path from "path";
import { pipFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { FilePathToContent } from "../../../lib/analyzer/applications/types";
import { getFixture } from "../../util";

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
});
