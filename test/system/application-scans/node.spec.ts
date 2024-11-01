import { DepGraph } from "@snyk/dep-graph";
import { legacy } from "@snyk/dep-graph";
import * as lockFileParser from "snyk-nodejs-lockfile-parser";
import * as resolveDeps from "snyk-resolve-deps";
import { scan } from "../../../lib";
import * as nodeUtils from "../../../lib/analyzer/applications/node-modules-utils";
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

  it("should generate a scanResult for a multi-project-image", async () => {
    const imageWithoutLockFile = getFixture("npm/multi-project-image.tar");
    const imageWithoutLockFileNameAndTag = `docker-archive:${imageWithoutLockFile}`;

    const { scanResults } = await scan({
      path: imageWithoutLockFileNameAndTag,
    });

    expect(scanResults).toMatchSnapshot();
    expect(scanResults.length).toEqual(5);
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

    const yarnCacheFilesGroupedByDir = nodeUtils.groupFilesByDirectory(
      yarnCacheFilesToContent,
    );

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
    const npmCacheFilesGroupedByDir = nodeUtils.groupFilesByDirectory(
      npmCacheFilesToContent,
    );

    expect(npmCacheFilesGroupedByDir.size).toBe(0);
  });

  it("should correctly filter unix cache files by default cache directory", async () => {
    const yarnNpmCacheFilesToContent: FilePathToContent = {
      "/home/user/.npm/_cache/registry.npm/@babel/core@7.20.0/node_modules/@babel/helper-function-name@7.18.3/node_modules/@babel/types@7.20.0/package.json":
        "",
      "/.yarn/cache/v6/@scope/package-name@1.0.0/8765432109876543210987654321098765432109876543210987654321098765/node_modules/react-router-dom@6.4.3/node_modules/history@5.3.0/package.json":
        "",
    };

    const yarnCacheFilesGroupedByDir = nodeUtils.groupFilesByDirectory(
      yarnNpmCacheFilesToContent,
    );

    expect(yarnCacheFilesGroupedByDir.size).toBe(0);
  });

  it("should correctly filter Windows cache files by default cache directory", async () => {
    const yarnNpmCacheFilesToContent: FilePathToContent = {
      "C:\\Users\\JohnDoe\\AppData\\Roaming\\npm-cache\\registry.npm\\react-router-dom@6.4.3\\node_modules\\history@5.3.0\\node_modules\\prop-types@15.8.1\\package.json":
        "",
      "C:\\Users\\JaneDoe\\AppData\\Roaming\\yarn\\cache\\v7\\@babel\\core@7.20.0\\node_modules\\@babel\\helper-function-name@7.18.3\\node_modules\\@babel\\types@7.20.0\\package.json":
        "",
    };

    const yarnCacheFilesGroupedByDir = nodeUtils.groupFilesByDirectory(
      yarnNpmCacheFilesToContent,
    );

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

    const yarnManifestsGrouped = nodeUtils.groupFilesByDirectory(
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
      nodeUtils.groupFilesByDirectory(npmCacheFilePaths);
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

    const pnpmManifestsGrouped = nodeUtils.groupFilesByDirectory(
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

    const filebyDirGroups = nodeUtils.groupFilesByDirectory(nodeAppFiles);

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
});

describe("Edge testing of node modules scan utils functions", () => {
  it("Exceptions should be handled", async () => {
    expect(() => nodeUtils.cleanupAppNodeModules("")).not.toThrow();

    expect(() => nodeUtils.groupFilesByDirectory({ "": "" })).not.toThrow();
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
