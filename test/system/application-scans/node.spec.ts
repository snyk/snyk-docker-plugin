import { DepGraph } from "@snyk/dep-graph";
import { legacy } from "@snyk/dep-graph";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import * as resolveDeps from "snyk-resolve-deps";
import { scan } from "../../../lib";
import { getFixture, getObjFromFixture } from "../../util";

describe("node application scans", () => {
  it("should correctly return applications as multiple scan results", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    expect(pluginResult).toMatchSnapshot();
    expect(pluginResult.scanResults).toHaveLength(3);
  });

  it("should correctly return applications as multiple scan results without the app-vulns option", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
    expect(pluginResult.scanResults).toHaveLength(3);
  });

  it("should handle --exclude-app-vulns with string and boolean value", async () => {
    const fixturePath = getFixture(
      "docker-archives/skopeo-copy/rpm-npm-yarn.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResultExcludeAppVulnsFalseString = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": "false",
    });

    const pluginResultExcludeAppVulnsTrueString = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": "true",
    });

    const pluginResultExcludeAppVulnsFalseBoolean = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": false,
    });

    const pluginResultExcludeAppVulnsTrueBoolean = await scan({
      path: imageNameAndTag,
      "exclude-app-vulns": true,
    });

    expect(pluginResultExcludeAppVulnsFalseString.scanResults).toHaveLength(3);
    expect(pluginResultExcludeAppVulnsFalseBoolean.scanResults).toHaveLength(3);

    expect(pluginResultExcludeAppVulnsTrueString.scanResults).toHaveLength(1);
    expect(pluginResultExcludeAppVulnsTrueBoolean.scanResults).toHaveLength(1);
  });

  it("ScanResult contains a npm7 depGraph generated from node modules manifest files", async () => {
    const imageWithManifestFiles = getFixture(
      "npm/npm-without-lockfiles/npm7-with-package-lock-file.tar",
    );
    const imageWithoutManifestFiles = getFixture(
      "npm/npm-without-lockfiles/npm7-without-package-lock-file.tar",
    );
    const imageWithManifestFilesNameAndTag = `docker-archive:${imageWithManifestFiles}`;
    const imageWithoutManifestFilesNameAndTag = `docker-archive:${imageWithoutManifestFiles}`;

    const pluginResultFromManifestFiles = await scan({
      path: imageWithManifestFilesNameAndTag,
      "app-vulns": true,
    });

    const pluginResultFromNodeModules = await scan({
      path: imageWithoutManifestFilesNameAndTag,
      "app-vulns": true,
    });

    const depGraphNpmFromManifestFiles: DepGraph =
      pluginResultFromManifestFiles.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    const depGraphNpmFromNodeModules: DepGraph =
      pluginResultFromNodeModules.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    expect(depGraphNpmFromManifestFiles.pkgManager.name).toEqual("npm");
    expect(depGraphNpmFromManifestFiles.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromManifestFiles.rootPkg.version).toBe("1.0.1");
    expect(depGraphNpmFromManifestFiles.getPkgs().length).toEqual(65); // approximate to the number reported by snyk test --dev
    expect(depGraphNpmFromNodeModules.pkgManager.name).toEqual("npm");
    expect(depGraphNpmFromNodeModules.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromNodeModules.rootPkg.version).toBe("1.0.1");
    // dev dependencies are reported
    expect(depGraphNpmFromNodeModules.getPkgs().length).toEqual(65);
  });

  it("ScanResult contains a npm7 depGraph when package.json | package-lock.json is missing from app", async () => {
    const imageWithNodeModules = getFixture(
      "npm/npm-without-lockfiles/npm7-with-node-modules-only.tar",
    );
    const imageWithoutLockFile = getFixture(
      "npm/npm-without-lockfiles/npm7-without-package-lock-file.tar",
    );
    const imageWithNodeModulesNameAndTag = `docker-archive:${imageWithNodeModules}`;
    const imageWithoutLockFileNameAndTag = `docker-archive:${imageWithoutLockFile}`;

    const pluginResultFromNodeModulesImage = await scan({
      path: imageWithNodeModulesNameAndTag,
      "app-vulns": true,
    });

    const pluginResultWithoutLockFile = await scan({
      path: imageWithoutLockFileNameAndTag,
      "app-vulns": true,
    });

    const depGraphNpmFromWithoutLockFiles: DepGraph =
      pluginResultWithoutLockFile.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    const depGraphNpmFromNodeModules: DepGraph =
      pluginResultFromNodeModulesImage.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    expect(depGraphNpmFromWithoutLockFiles.pkgManager.name).toEqual("npm");
    expect(depGraphNpmFromWithoutLockFiles.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromWithoutLockFiles.rootPkg.version).toBe("1.0.1");
    expect(depGraphNpmFromWithoutLockFiles.getPkgs().length).toEqual(65);
    expect(depGraphNpmFromNodeModules.pkgManager.name).toEqual("npm");
    // when both package.json and package-lock.json is missing root package is the name of the application dir
    // and the version for the root package remains undefined and the dev dependencies are reported
    expect(depGraphNpmFromNodeModules.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromNodeModules.rootPkg.version).toBe(undefined);
    expect(depGraphNpmFromNodeModules.getPkgs().length).toEqual(65);
  });

  it("Scan result contains a yarn depgraph generated from node modules manifest files", async () => {
    const imageWithManifestFiles = getFixture(
      "npm/npm-without-lockfiles/yarn-with-lock-file.tar",
    );
    const imageWithoutManifestFiles = getFixture(
      "npm/npm-without-lockfiles/yarn-without-lock-file.tar",
    );
    const imageWithManifestFilesNameAndTag = `docker-archive:${imageWithManifestFiles}`;
    const imageWithoutManifestFilesNameAndTag = `docker-archive:${imageWithoutManifestFiles}`;

    const pluginResultFromManifestFiles = await scan({
      path: imageWithManifestFilesNameAndTag,
      "app-vulns": true,
    });

    const pluginResultFromNodeModules = await scan({
      path: imageWithoutManifestFilesNameAndTag,
      "app-vulns": true,
    });

    const depGraphNpmFromManifestFiles: DepGraph =
      pluginResultFromManifestFiles.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    const depGraphNpmFromNodeModules: DepGraph =
      pluginResultFromNodeModules.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    expect(depGraphNpmFromManifestFiles.pkgManager.name).toEqual("yarn");
    expect(depGraphNpmFromManifestFiles.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromManifestFiles.rootPkg.version).toBe("1.0.1");
    expect(depGraphNpmFromManifestFiles.getPkgs().length).toEqual(65); // approximate to the number reported by snyk test --dev
    expect(depGraphNpmFromNodeModules.pkgManager.name).toEqual("npm");
    expect(depGraphNpmFromNodeModules.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromNodeModules.rootPkg.version).toBe("1.0.1");
    // dev dependencies are reported
    expect(depGraphNpmFromNodeModules.getPkgs().length).toEqual(65);
  });

  it("ScanResult contains a yarn depGraph package.json | package-lock.json is missing from the app", async () => {
    const imageWithNodeModules = getFixture(
      "npm/npm-without-lockfiles/yarn-with-node-modules-only.tar",
    );
    const imageWithoutLockFile = getFixture(
      "npm/npm-without-lockfiles/yarn-without-lock-file.tar",
    );
    const imageWithNodeModulesNameAndTag = `docker-archive:${imageWithNodeModules}`;
    const imageWithoutLockFileNameAndTag = `docker-archive:${imageWithoutLockFile}`;

    const pluginResultFromNodeModulesImage = await scan({
      path: imageWithNodeModulesNameAndTag,
      "app-vulns": true,
    });

    const pluginResultWithoutLockFile = await scan({
      path: imageWithoutLockFileNameAndTag,
      "app-vulns": true,
    });

    const depGraphNpmFromWithoutLockFiles: DepGraph =
      pluginResultWithoutLockFile.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    const depGraphNpmFromNodeModules: DepGraph =
      pluginResultFromNodeModulesImage.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    expect(depGraphNpmFromWithoutLockFiles.pkgManager.name).toEqual("npm");
    expect(depGraphNpmFromWithoutLockFiles.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromWithoutLockFiles.rootPkg.version).toBe("1.0.1");
    expect(depGraphNpmFromWithoutLockFiles.getPkgs().length).toEqual(65);
    expect(depGraphNpmFromNodeModules.pkgManager.name).toEqual("npm");
    // when both package.json and package-lock.json is missing root package is the name of the application dir
    // and the version for the root package remains undefined and the dev dependencies are reported
    expect(depGraphNpmFromNodeModules.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromNodeModules.rootPkg.version).toBe(undefined);
    expect(depGraphNpmFromNodeModules.getPkgs().length).toEqual(65);
  });

  it("resolveDeps should return a depGraph constructed from node_modules when the application dir doesn't contain the package.json file", async () => {
    const fixturePath = getFixture("/npm/npm-without-lockfiles/home/app/");
    const expectedDepgraphJson = getObjFromFixture(
      "npm/npm-without-lockfiles/resolveDepsResultEmptyPackage.json",
    );
    const depRes: lockFileParser.PkgTree = await resolveDeps(fixturePath, {
      dev: true,
      noFromArrays: true,
    });

    const depGraph = await legacy.depTreeToGraph(depRes, "npm");

    expect(depGraph.rootPkg.name).toEqual("app");
    expect(depGraph.rootPkg.version).toBe(undefined);
    expect(depGraph.toJSON()).toEqual(expectedDepgraphJson);
  });
});
