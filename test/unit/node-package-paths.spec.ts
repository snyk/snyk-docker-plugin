import { collectNodeModulesPackagePaths } from "../../lib/analyzer/applications/node";
import {
  FilePathToContent,
  FilesByDirMap,
} from "../../lib/analyzer/applications/types";

describe("collectNodeModulesPackagePaths", () => {
  const project = "/usr/lib";

  function pkgJson(name: string, version: string): string {
    return JSON.stringify({ name, version });
  }

  it("collects name/version/installDir for each node_modules package.json", () => {
    const braceDir = "/usr/lib/node_modules/npm/node_modules/brace-expansion";
    const semverDir = "/usr/lib/node_modules/npm/node_modules/semver";
    const files: FilesByDirMap = new Map([
      [
        project,
        new Set([
          `${braceDir}/package.json`,
          `${semverDir}/package.json`,
          "/usr/lib/node_modules/npm/package.json",
        ]),
      ],
    ]);
    const contents: FilePathToContent = {
      [`${braceDir}/package.json`]: pkgJson("brace-expansion", "2.0.1"),
      [`${semverDir}/package.json`]: pkgJson("semver", "7.6.0"),
      ["/usr/lib/node_modules/npm/package.json"]: pkgJson("npm", "10.9.0"),
    };

    const result = collectNodeModulesPackagePaths(project, files, contents);

    expect(result).toEqual(
      expect.arrayContaining([
        { name: "brace-expansion", version: "2.0.1", installDir: braceDir },
        { name: "semver", version: "7.6.0", installDir: semverDir },
        {
          name: "npm",
          version: "10.9.0",
          installDir: "/usr/lib/node_modules/npm",
        },
      ]),
    );
    expect(result).toHaveLength(3);
  });

  it("skips pnpm/.bin virtual entries and root manifests outside node_modules", () => {
    const files: FilesByDirMap = new Map([
      [
        project,
        new Set([
          "/usr/lib/node_modules/.pnpm/foo@1.0.0/node_modules/foo/package.json",
          "/usr/lib/node_modules/.bin/whatever/package.json",
          "/usr/lib/package.json", // root manifest, not under node_modules
        ]),
      ],
    ]);
    const contents: FilePathToContent = {
      "/usr/lib/node_modules/.pnpm/foo@1.0.0/node_modules/foo/package.json":
        pkgJson("foo", "1.0.0"),
      "/usr/lib/node_modules/.bin/whatever/package.json": pkgJson("x", "1"),
      "/usr/lib/package.json": pkgJson("root", "1.0.0"),
    };

    expect(collectNodeModulesPackagePaths(project, files, contents)).toEqual(
      [],
    );
  });

  it("skips package.json with missing name/version or invalid JSON", () => {
    const files: FilesByDirMap = new Map([
      [
        project,
        new Set([
          "/usr/lib/node_modules/no-version/package.json",
          "/usr/lib/node_modules/broken/package.json",
        ]),
      ],
    ]);
    const contents: FilePathToContent = {
      "/usr/lib/node_modules/no-version/package.json": JSON.stringify({
        name: "no-version",
      }),
      "/usr/lib/node_modules/broken/package.json": "{ not json",
    };

    expect(collectNodeModulesPackagePaths(project, files, contents)).toEqual(
      [],
    );
  });

  it("handles scoped packages (@scope/name)", () => {
    const scopedDir = "/usr/lib/node_modules/npm/node_modules/@npmcli/agent";
    const files: FilesByDirMap = new Map([
      [project, new Set([`${scopedDir}/package.json`])],
    ]);
    const contents: FilePathToContent = {
      [`${scopedDir}/package.json`]: pkgJson("@npmcli/agent", "4.0.2"),
    };

    expect(collectNodeModulesPackagePaths(project, files, contents)).toEqual([
      { name: "@npmcli/agent", version: "4.0.2", installDir: scopedDir },
    ]);
  });

  it("returns one entry per install path for a coordinate at multiple depths", () => {
    // Collection does not dedup; the resolver dedups by coordinate. This keeps
    // both install locations available so ownership can be resolved per path.
    const hoisted = "/usr/lib/node_modules/npm/node_modules/semver";
    const nested =
      "/usr/lib/node_modules/npm/node_modules/foo/node_modules/semver";
    const files: FilesByDirMap = new Map([
      [project, new Set([`${hoisted}/package.json`, `${nested}/package.json`])],
    ]);
    const contents: FilePathToContent = {
      [`${hoisted}/package.json`]: pkgJson("semver", "7.6.0"),
      [`${nested}/package.json`]: pkgJson("semver", "7.6.0"),
    };

    const result = collectNodeModulesPackagePaths(project, files, contents);
    expect(result).toHaveLength(2);
    expect(result.map((p) => p.installDir).sort()).toEqual(
      [hoisted, nested].sort(),
    );
  });

  it("returns empty when the project has no grouped files", () => {
    expect(collectNodeModulesPackagePaths("/missing", new Map(), {})).toEqual(
      [],
    );
  });
});
