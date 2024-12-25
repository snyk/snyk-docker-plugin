import { InvalidUserInputError } from "@snyk/composer-lockfile-parser/dist/errors";
import { DepGraph } from "@snyk/dep-graph";
import { legacy } from "@snyk/dep-graph";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import { NodeLockfileVersion } from "snyk-nodejs-lockfile-parser";
import * as resolveDeps from "snyk-resolve-deps";
import { scan } from "../../../lib";
import {
  getLockFileVersion,
  shouldBuildDepTree,
} from "../../../lib/analyzer/applications/node";
import * as nodeUtils from "../../../lib/analyzer/applications/node-modules-utils";
import { getAppFilesRootDir } from "../../../lib/analyzer/applications/runtime-common";
import { FilePathToContent } from "../../../lib/analyzer/applications/types";
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

  it("should correctly return depgraph for yarn lockfiles V1 and V2", async () => {
    const fixturePathYarnV1 = getFixture("/yarn/yarnlockv1.tar");

    const fixturePathYarnV2 = getFixture("/yarn/yarnlockv2.tar");
    const imageNameAndTagV1 = `docker-archive:${fixturePathYarnV1}`;
    const imageNameAndTagV2 = `docker-archive:${fixturePathYarnV2}`;

    const pluginResultYarnV1 = await scan({
      path: imageNameAndTagV1,
      "app-vulns": true,
    });

    const pluginResultYarnV2 = await scan({
      path: imageNameAndTagV2,
      "app-vulns": true,
    });

    const depGraphYarnV1: DepGraph =
      pluginResultYarnV1.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    const depGraphYarnV2: DepGraph =
      pluginResultYarnV2.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    expect(depGraphYarnV1.pkgManager.name).toEqual("yarn");
    expect(depGraphYarnV2.pkgManager.name).toEqual("yarn");
    expect(depGraphYarnV1.getPkgs().length).toEqual(
      depGraphYarnV2.getPkgs().length,
    );
    expect(depGraphYarnV1.getDepPkgs().length).toEqual(
      depGraphYarnV2.getDepPkgs().length,
    );
    expect(pluginResultYarnV1).toMatchSnapshot();
    expect(pluginResultYarnV2).toMatchSnapshot();
  });

  it("should correctly return depgraph for npm lockfiles V2 and V3", async () => {
    const fixturePathNpmV2 = getFixture("/npm/npmlockv2.tar");

    const fixturePathNpmV3 = getFixture("/npm/npmlockv3.tar");
    const imageNameAndTagV2 = `docker-archive:${fixturePathNpmV2}`;
    const imageNameAndTagV3 = `docker-archive:${fixturePathNpmV3}`;

    const pluginResultNpmV2 = await scan({
      path: imageNameAndTagV2,
      "app-vulns": true,
    });

    const pluginResultNpmV3 = await scan({
      path: imageNameAndTagV3,
      "app-vulns": true,
    });

    const depGraphNpmV2: DepGraph = pluginResultNpmV2.scanResults[1].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    const depGraphNpmV3: DepGraph = pluginResultNpmV3.scanResults[1].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    expect(depGraphNpmV2.pkgManager.name).toEqual("npm");
    expect(depGraphNpmV3.pkgManager.name).toEqual("npm");
    expect(depGraphNpmV2.getPkgs().length).toEqual(
      depGraphNpmV3.getPkgs().length,
    );
    expect(depGraphNpmV2.getDepPkgs().length).toEqual(
      depGraphNpmV3.getDepPkgs().length,
    );
    expect(pluginResultNpmV2).toMatchSnapshot();
    expect(pluginResultNpmV3).toMatchSnapshot();
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

  it("should handle --collect-application-files", async () => {
    const fixturePath = getFixture("npm/multi-project-image.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const resultWithoutApplicationFilesFlag = await scan({
      path: imageNameAndTag,
    });
    const resultWithApplicationFilesFlagSetToTrue = await scan({
      path: imageNameAndTag,
      "collect-application-files": "true",
    });

    expect(resultWithoutApplicationFilesFlag.scanResults).toHaveLength(5);
    expect(resultWithApplicationFilesFlagSetToTrue.scanResults).toHaveLength(6);

    const appFiles =
      resultWithApplicationFilesFlagSetToTrue.scanResults[5].facts.find(
        (fact) => fact.type === "applicationFiles",
      )!.data;
    expect(appFiles.length).toEqual(1);
    expect(appFiles[0].fileHierarchy.length).toEqual(4);
    expect(appFiles[0].language).toEqual("node");
    expect(appFiles[0].fileHierarchy).toStrictEqual([
      { path: "bin/yarn.js" },
      { path: "lib/cli.js" },
      { path: "lib/v8-compile-cache.js" },
      { path: "package.json" },
    ]);
  });

  it("should not create scan results for the npm/yarn cache directories", async () => {
    const fixturePath = getFixture(
      "npm/npm-without-lockfiles/node-image-with-caches.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    const depGraphNpmFromApkPackages: DepGraph =
      pluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    const depGraphNpmFromGoofNodeModules: DepGraph =
      pluginResult.scanResults[1].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;

    const depGraphNpmFromGlobalNodeModules: DepGraph =
      pluginResult.scanResults[2].facts.find(
        (fact) => fact.type === "depGraph",
      )!.data;
    expect(pluginResult.scanResults).toHaveLength(3);
    expect(depGraphNpmFromApkPackages.rootPkg.name).toEqual(
      "docker-image|node-image-with-caches.tar",
    );
    expect(depGraphNpmFromGoofNodeModules.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromGlobalNodeModules.rootPkg.name).toEqual("lib");
  });

  it("should generate a scanResult that contains a npm7 depGraph generated from node modules manifest files", async () => {
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
    expect(depGraphNpmFromManifestFiles.getPkgs().length).toBeGreaterThan(64);
    expect(depGraphNpmFromNodeModules.pkgManager.name).toEqual("npm");
    expect(depGraphNpmFromNodeModules.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromNodeModules.rootPkg.version).toBe("1.0.1");
    // dev dependencies are reported
    expect(depGraphNpmFromNodeModules.getPkgs().length).toBeGreaterThan(64);
  });

  it("should generate a scanResult that contains a yarn depgraph generated from node modules manifest files", async () => {
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
    expect(depGraphNpmFromManifestFiles.getPkgs().length).toBeGreaterThan(64);
    expect(depGraphNpmFromNodeModules.pkgManager.name).toEqual("npm");
    expect(depGraphNpmFromNodeModules.rootPkg.name).toEqual("goof");
    expect(depGraphNpmFromNodeModules.rootPkg.version).toBe("1.0.1");
    // dev dependencies are reported
    expect(depGraphNpmFromNodeModules.getPkgs().length).toBeGreaterThan(64);
  });

  it("should generate a scanResult from multiple node.js projects inside a multi-project-image", async () => {
    const imageWithoutLockFile = getFixture("npm/multi-project-image.tar");
    const imageWithoutLockFileNameAndTag = `docker-archive:${imageWithoutLockFile}`;

    const { scanResults } = await scan({
      path: imageWithoutLockFileNameAndTag,
      platform: "linux/amd64",
    });

    expect(scanResults).toMatchSnapshot();
    expect(scanResults.length).toEqual(5);
  });

  it("should exclude scanning of node_modules projects from a node.js container image", async () => {
    const imageWithoutLockFile = getFixture("npm/multi-project-image.tar");
    const imageWithoutLockFileNameAndTag = `docker-archive:${imageWithoutLockFile}`;

    const { scanResults } = await scan({
      path: imageWithoutLockFileNameAndTag,
      platform: "linux/amd64",
      "exclude-node-modules": true,
    });

    expect(scanResults).toMatchSnapshot();
    expect(scanResults.length).toEqual(2);
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

  it("should generate a scanResult with the correct number of deps if npm lockfile V1", async () => {
    const imageWithV1Lockfile = getFixture(
      "docker-archives/docker-save/packagelockv1.tar",
    );

    const imageWithV1LockfileNameAndTag = `docker-archive:${imageWithV1Lockfile}`;

    const pluginResult = await scan({
      path: imageWithV1LockfileNameAndTag,
      "app-vulns": true,
      platform: "linux/arm64",
    });

    const depGraph: DepGraph = pluginResult.scanResults[1].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    expect(depGraph.pkgManager.name).toEqual("npm");
    expect(depGraph.rootPkg.name).toEqual("packlockv1test");
    expect(depGraph.rootPkg.version).toBe("1.0.0");
    expect(depGraph.getPkgs().length).toEqual(238);
  });

  it("should generate a scanResult with the correct number of deps if npm lockfile V2", async () => {
    const imageWithV2Lockfile = getFixture(
      "docker-archives/docker-save/packagelockv2.tar",
    );

    const imageWithV2LockfileNameAndTag = `docker-archive:${imageWithV2Lockfile}`;

    const pluginResult = await scan({
      path: imageWithV2LockfileNameAndTag,
      "app-vulns": true,
      platform: "linux/arm64",
    });

    const depGraph: DepGraph = pluginResult.scanResults[1].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    expect(depGraph.pkgManager.name).toEqual("npm");
    expect(depGraph.rootPkg.name).toEqual("packlockv2test");
    expect(depGraph.rootPkg.version).toBe("1.0.0");
    expect(depGraph.getPkgs().length).toEqual(238);
  });

  it("should generate a scanResult with the correct number of deps if npm lockfile V3", async () => {
    const imageWithV3Lockfile = getFixture(
      "docker-archives/docker-save/packagelockv3.tar",
    );

    const imageWithV3LockfileNameAndTag = `docker-archive:${imageWithV3Lockfile}`;

    const pluginResult = await scan({
      path: imageWithV3LockfileNameAndTag,
      "app-vulns": true,
      platform: "linux/arm64",
    });

    const depGraph: DepGraph = pluginResult.scanResults[1].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;

    expect(depGraph.pkgManager.name).toEqual("npm");
    expect(depGraph.rootPkg.name).toEqual("packlockv3test");
    expect(depGraph.rootPkg.version).toBe("1.0.0");
    expect(depGraph.getPkgs().length).toEqual(238);
  });
});

describe("shouldBuildDepTree", () => {
  it("should return false for lockfile versions that don't need to be converted to a deptree", () => {
    expect(shouldBuildDepTree(NodeLockfileVersion.YarnLockV1)).toBe(false);
    expect(shouldBuildDepTree(NodeLockfileVersion.YarnLockV2)).toBe(false);
    expect(shouldBuildDepTree(NodeLockfileVersion.NpmLockV2)).toBe(false);
    expect(shouldBuildDepTree(NodeLockfileVersion.NpmLockV3)).toBe(false);
  });

  it("should return true for lockfile versions that need to be converted to a deptree before creating a depgraph", () => {
    expect(shouldBuildDepTree(NodeLockfileVersion.PnpmLockV6)).toBe(true);
    expect(shouldBuildDepTree(NodeLockfileVersion.PnpmLockV9)).toBe(true);
  });
});

describe("getLockFileVersion", () => {
  it("should return the correct lockfile version for package-lock.json files", () => {
    const lockFileContentsV2 = `{
      "name": "my-package",
      "version": "1.0.0",
      "lockfileVersion": 2
    }`;
    expect(getLockFileVersion("package-lock.json", lockFileContentsV2)).toBe(
      NodeLockfileVersion.NpmLockV2,
    );

    const lockFileContentsV3 = `{
      "name": "my-package",
      "version": "1.0.0",
      "lockfileVersion": 3
    }`;
    expect(getLockFileVersion("package-lock.json", lockFileContentsV3)).toBe(
      NodeLockfileVersion.NpmLockV3,
    );
  });

  it("should return the correct lockfile version for yarn.lock files", () => {
    const lockFileContentsV1 = `
    "@babel/code-frame@^7.0.0":
      version "7.10.4"
      resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#5921a64682d41d2bc04d489a692978e7707c687c"
      dependencies:
        "@babel/highlight" "^7.9.0"
    `;
    expect(getLockFileVersion("yarn.lock", lockFileContentsV1)).toBe(
      NodeLockfileVersion.YarnLockV1,
    );

    const lockFileContentsV2 = `
    __metadata:
    version: 5
    cacheVersion: 1
    "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
      version "7.10.4"
      resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#5921a64682d41d2bc04d489a692978e7707c687c"
      integrity sha512-vG6o+vMVW+B6B7wXq+VH8EaRQwkS45QisGu4UdLUh6A+pmnG7jNyo/n2+jkaOmYc+Cf+Z6pPqh3BTqW+KFoJg==
      dependencies:
        "@babel/highlight" "^7.9.0"
    `;
    expect(getLockFileVersion("yarn.lock", lockFileContentsV2)).toBe(
      NodeLockfileVersion.YarnLockV2,
    );
  });

  it("should return the correct lockfile version for pnpm-lock.yaml files", () => {
    const lockFileContentsV6 = `
    lockfileVersion: 6
    dependencies:
      debug: 4.3.1
    `;
    expect(getLockFileVersion("pnpm-lock.yaml", lockFileContentsV6)).toBe(
      NodeLockfileVersion.PnpmLockV6,
    );

    const lockFileContentsV9 = `
    lockfileVersion: 9
    dependencies:
      debug: 4.3.1
    `;
    expect(getLockFileVersion("pnpm-lock.yaml", lockFileContentsV9)).toBe(
      NodeLockfileVersion.PnpmLockV9,
    );
  });

  it("should throw an error for unknown lockfile names", () => {
    const lockFileContents = `{
      "name": "my-package",
      "version": "1.0.0"
    }`;
    expect(() =>
      getLockFileVersion("unknown.lock", lockFileContents),
    ).toThrowError(InvalidUserInputError);
  });
});

describe("node application files grouping", () => {
  it("should correctly filter unix yarn/npm cache manifest files", async () => {
    const yarnCacheFilesToContent: FilePathToContent = {
      "/usr/local/share/.cache/yarn/v6/npm-@dep-compat-data-7.23.5/package.json":
        "",
      "/usr/local/share/.yarn/cache/v6/npm-@dep-compat-data-7.23.5/package.json":
        "",
      "/usr/local/share/.cache/yarn/v6/npm-@dep-compat-data-7.21.5/package.json":
        "",
      "/usr/local/share/.yarn/cache/v6/npm-deep-is-0.1.4/package.json": "",
      "/home/user/.cache/yarn/v1/package.json": "",
      "/home/user/.cache/yarn/v1/package-lock.json": "",
      "/home/user/.cache/yarn/v2/yarn.lock": "",
      "/home/user/.cache/yarn/v2/package.json": "",
      "/usr/local/share/.cache/yarn/v6/npm-@babel-helper-create-class-features-plugin-7.23.6/package.json":
        "",
    };

    const yarnCacheFilesGroupedByDir =
      nodeUtils.groupNodeModulesFilesByDirectory(yarnCacheFilesToContent);

    expect(yarnCacheFilesGroupedByDir.size).toBe(0);

    const npmCacheFilesToContent: FilePathToContent = {
      "/home/user/.npm/_cacache/content-v2/package-lock.json": "",
      "/home/user/.npm/_cacache/content-v2/package.json": "",
      "/home/user/.npm/_cacache/content-v3/package.json": "",
      "/home/user/.npm/_cacache/content-v3/node_modules/tmp/package.json": "",
      "/home/user/.npm/_cache/package-lock.json": "",
      "/home/user/.npm/_cache/package.json": "",
      "/.cache/package.json/.npm/_cache/registry.npm/@scope/package-name@1.0.0/package-lock.json":
        "",
    };
    const npmCacheFilesGroupedByDir =
      nodeUtils.groupNodeModulesFilesByDirectory(npmCacheFilesToContent);

    expect(npmCacheFilesGroupedByDir.size).toBe(0);
  });

  it("should correctly filter unix cache files by default cache directory", async () => {
    const yarnNpmCacheFilesToContent: FilePathToContent = {
      "/home/user/.npm/_cache/registry.npm/@babel/core@7.20.0/node_modules/@babel/helper-function-name@7.18.3/node_modules/@babel/types@7.20.0/package.json":
        "",
      "/.yarn/cache/v6/@scope/package-name@1.0.0/8765432109876543210987654321098765432109876543210987654321098765/node_modules/react-router-dom@6.4.3/node_modules/history@5.3.0/package.json":
        "",
    };

    const yarnCacheFilesGroupedByDir =
      nodeUtils.groupNodeModulesFilesByDirectory(yarnNpmCacheFilesToContent);

    expect(yarnCacheFilesGroupedByDir.size).toBe(0);
  });

  it("should correctly filter Windows cache files by default cache directory", async () => {
    const yarnNpmCacheFilesToContent: FilePathToContent = {
      "C:\\Users\\JohnDoe\\AppData\\Roaming\\npm-cache\\registry.npm\\react-router-dom@6.4.3\\node_modules\\history@5.3.0\\node_modules\\prop-types@15.8.1\\package.json":
        "",
      "C:\\Users\\JaneDoe\\AppData\\Roaming\\yarn\\cache\\v7\\@babel\\core@7.20.0\\node_modules\\@babel\\helper-function-name@7.18.3\\node_modules\\@babel\\types@7.20.0\\package.json":
        "",
    };

    const yarnCacheFilesGroupedByDir =
      nodeUtils.groupNodeModulesFilesByDirectory(yarnNpmCacheFilesToContent);

    expect(yarnCacheFilesGroupedByDir.size).toBe(0);
  });

  it("should correctly filter Windows yarn/npm cache manifest files by default cache directory", async () => {
    const yarnCacheFilePathstoContent = {
      "C:\\Users\\YourUsername\\AppData\\Roaming\\yarn\\cache\\v6\\@scope\\package-name@1.0.0\\package.json":
        "",
      "C:\\Users\\YourUsername\\AppData\\Roaming\\yarn\\cache\\v3\\@scope\\package-name@1.0.0\\package-lock.json":
        "",
      "C:\\Users\\YourUsername\\AppData\\Roaming\\yarn\\cache\\v9\\registry.npm\\lodash@4.17.21\\package-lock.json":
        "",
    };

    const yarnManifestsGrouped = nodeUtils.groupNodeModulesFilesByDirectory(
      yarnCacheFilePathstoContent,
    );

    expect(yarnManifestsGrouped.size).toBe(0);
    const npmCacheFilePaths = {
      "C:\\Users\\YourUsername\\AppData\\Roaming\\npm-cache\\registry.npm\\@scope\\package-name@1.0.0\\package-lock.json":
        "",
      "C:\\Users\\YourUsername\\AppData\\Roaming\\npm-cache\\registry.npm\\@scope\\package-name@1.0.0\\package.tgz":
        "",
      "C:\\Users\\YourUsername\\AppData\\Roaming\\npm-cache\\registry.npm\\@scope\\package-name@1.0.0\\package.json":
        "",
    };

    const npmManifestsGrouped =
      nodeUtils.groupNodeModulesFilesByDirectory(npmCacheFilePaths);
    expect(npmManifestsGrouped.size).toBe(0);
  });

  it("should correctly filter pnpm cache manifest files by default cache directory", async () => {
    const pnpmCacheFilePathstoContent = {
      " ~/.pnpm-store/54321098765432109876543210987654321098765432109876543210987654321/workspace-root/package.json":
        "",
      " ~/pnpm/store/54321098765432109876543210987654321098765432109876543210987654321/workspace-root/package.json":
        "",
      "~/.pnpm-store/54321098765432109876543210987654321098765432109876543210987654321/package.json":
        "",
      "~/.pnpm-store/54321098765432109876543210987654321098765432109876543210987654321/node_modules/@scope/package-a@1.2.3/package.json":
        "",
      "C:\\Users\\username\\AppData\\Roaming\\pnpm-store\\54321098765432109876543210987654321098765432109876543210987654321\\package.json":
        "",
      "C:\\Users\\username\\AppData\\Roaming\\pnpm\\store\\54321098765432109876543210987654321098765432109876543210987654321\\package.json":
        "",
    };

    const pnpmManifestsGrouped = nodeUtils.groupNodeModulesFilesByDirectory(
      pnpmCacheFilePathstoContent,
    );

    expect(pnpmManifestsGrouped.size).toBe(0);
  });

  it("should correctly group npm/yarn manifest files by parent directory", async () => {
    const nodeAppFiles: FilePathToContent = {
      "/package.json": "", // project manifest mounted in root dir
      "/package-lock.json": "", // project lock  mounted in root dir
      "/node_modules/gopd/package.json": "", // project node_modules  mounted in root dir
      "/node_modules/gopd/node_modules/package.json": "",

      "/goof/package.json": "",
      "/goof/package-lock.json": "",
      "/goof/node_modules/gopd/package.json": "",
      "/goof/node_modules/gopd/node_modules/package.json": "",

      "/goof1/node_modules/gopd/package.json": "",
      "/goof1/node_modules/gopd/node_modules/package.json": "",
      "/goof1/package.json": "",

      "/goof2/node_modules/gopd/package.json": "",
      "/goof2/node_modules/gopd/node_modules/package.json": "",

      "/usr/local/lib/node_modules/tmp/package.json": "",
      "/usr/local/lib/package.json": "",

      "/opt/local/lib/node_modules/tmp/package.json": "",
      "/opt/local/lib/package.json": "",
    };

    const filebyDirGroups =
      nodeUtils.groupNodeModulesFilesByDirectory(nodeAppFiles);
    expect(filebyDirGroups.size).toBe(6);
    expect(Array.from(filebyDirGroups.keys())).toEqual([
      "/",
      "/goof",
      "/goof1",
      "/goof2",
      "/usr/local/lib",
      "/opt/local/lib",
    ]);
  });

  it("should correctly group js ts files with root dir", async () => {
    const nodeProjectFiles = [
      "/srv/dist/index.js",
      "/srv/dist/src/app.js",
      "/srv/dist/src/utils/helpers.js",
      "/srv/dist/src/components/header.ts",
      "/srv/dist/src/components/footer.js",
      "/srv/dist/src/services/api.js",
      "/srv/dist/src/models/user.js",
      "/srv/dist/src/config/config.ts",
      "/srv/dist/package.json",
      "/srv/dist/package-lock.json",
    ];

    const [appFilesRootDir, appFiles] = getAppFilesRootDir(nodeProjectFiles);

    expect(appFilesRootDir).toBe("/srv/dist");
    expect(appFiles.length).toBe(10);
    expect(appFiles).toEqual([
      { path: "index.js" },
      { path: "src/app.js" },
      { path: "src/utils/helpers.js" },
      { path: "src/components/header.ts" },
      { path: "src/components/footer.js" },
      { path: "src/services/api.js" },
      { path: "src/models/user.js" },
      { path: "src/config/config.ts" },
      { path: "package.json" },
      { path: "package-lock.json" },
    ]);
  });
});

describe("Edge testing of node modules scan utils functions", () => {
  it("Exceptions should be handled", async () => {
    expect(() => nodeUtils.cleanupAppNodeModules("")).not.toThrow();

    expect(() =>
      nodeUtils.groupNodeModulesFilesByDirectory({ "": "" }),
    ).not.toThrow();
    expect(() =>
      nodeUtils.persistNodeModules(
        "",
        { "": "" },
        new Map<string, Set<string>>(),
      ),
    ).not.toThrow();
    expect(
      await nodeUtils.persistNodeModules(
        "",
        { "": "" },
        new Map<string, Set<string>>(),
      ),
    ).toEqual({ tempDir: "", tempProjectPath: "" });
  });
});
