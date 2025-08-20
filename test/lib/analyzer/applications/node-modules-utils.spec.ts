import {
  groupNodeAppFilesByDirectory,
  groupNodeModulesFilesByDirectory,
} from "../../../../lib/analyzer/applications/node-modules-utils";

describe("node-modules-utils grouping", () => {
  it("groups app files by their directory", () => {
    const files = {
      "/a/b/package.json": "{}",
      "/a/b/index.js": "",
      "/a/c/file.js": "",
    };
    const byDir = groupNodeAppFilesByDirectory(files as any);
    expect(byDir.get("/a/b")?.size).toBe(2);
    expect(byDir.get("/a/c")?.size).toBe(1);
  });

  it("filters cache directories and groups by node_modules parent dir", () => {
    const files = {
      "/w/node_modules/foo/package.json": "{}",
      "/w/node_modules/foo/index.js": "",
      "/w/.npm/_cacache/some": "",
      "/w/.yarn/cache/some": "",
      "/w/pnpm-store/v3/index": "",
      "/w/node_modules/foo/bar/package.json": "{}",
    };
    const byDir = groupNodeModulesFilesByDirectory(files as any);
    // only files outside cache dirs should be present
    const dirs = [...byDir.keys()];
    expect(dirs).toEqual(["/w"]);
    expect(byDir.get("/w")?.size).toBe(3);
  });
});
