import {
  getAppFilesRootDir,
  getApplicationFiles,
} from "../../../../lib/analyzer/applications/runtime-common";

describe("runtime-common getAppFilesRootDir", () => {
  it("returns root '/' and empty when no files", () => {
    const [root, files] = getAppFilesRootDir([]);
    expect(root).toBe("/");
    expect(files).toEqual([]);
  });

  it("finds common root and returns relative paths", () => {
    const input = ["/repo/app/src/index.js", "/repo/app/test/spec.js"];
    const [root, files] = getAppFilesRootDir(input);
    expect(root).toBe("/repo/app");
    expect(files.map((f) => f.path).sort()).toEqual(
      ["src/index.js", "test/spec.js"].sort(),
    );
  });
});

describe("runtime-common getApplicationFiles", () => {
  it("produces a single scan result with applicationFiles fact and identity", () => {
    const filePathToContent = {
      "/root/app/a.txt": "a",
      "/root/app/b.txt": "b",
    } as const;
    const results = getApplicationFiles(
      filePathToContent,
      "javascript",
      "app-files",
    );
    expect(results).toHaveLength(1);
    const res = results[0];
    expect(res.identity).toEqual({
      type: "app-files",
      targetFile: "/root/app",
    });
    expect(res.facts[0].type).toBe("applicationFiles");
    const data = (res.facts[0] as any).data[0];
    expect(data.language).toBe("javascript");
    expect(Array.isArray(data.fileHierarchy)).toBe(true);
  });
});
