import {
  filesMetadataExtractorPerLanguage,
  getAppFileInfos,
  getRootDir,
} from "../../../lib/analyzer/applications/runtime-common";

describe("application files root dir extraction", () => {
  it("should correctly get root dir for js ts files", async () => {
    let nodeProjectFiles = [
      "/aaa/bbb/ccc/y.js",
      "/aaa/bbb/ccc/z.js",
      "/aaa/x.js",
    ];

    expect(getRootDir(nodeProjectFiles)).toBe("/aaa");

    nodeProjectFiles = [
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

    expect(getRootDir(nodeProjectFiles)).toBe("/srv/dist");
  });

  it("should return / as the root dir in case nothing's found", async () => {
    const nodeProjectFiles = ["/srv/dist/index.js", "/opt/app.js"];
    expect(getRootDir(nodeProjectFiles)).toBe("/");
  });

  it("should only consider full path segments for common prefix", async () => {
    const nodeProjectFiles = ["/srv/dist/index.js", "/srv2/app.js"];
    expect(getRootDir(nodeProjectFiles)).toBe("/");
  });

  it("should correctly get root dir for python application files", async () => {
    const pythonProjectFiles = [
      "/app/index.py",
      "/app/src/app.py",
      "/app/src/utils/helpers.py",
      "/app/src/components/header.py",
      "/app/src/components/footer.py",
      "/app/src/services/api.py",
      "/app/src/models/user.py",
      "/app/src/config/config.py",
      "/app/requirements.txt",
    ];
    expect(getRootDir(pythonProjectFiles)).toBe("/app");
  });
});

describe("application files info extraction", () => {
  it("should correctly get app infos for js ts files", async () => {
    const nodeProjectFiles = {
      "/aaa/bbb/ccc/y.js": "",
      "/aaa/bbb/ccc/z.js": "",
      "/aaa/x.js": "",
    };

    const appFiles = getAppFileInfos(
      nodeProjectFiles,
      "/aaa",
      filesMetadataExtractorPerLanguage.node,
    );
    expect(appFiles.length).toBe(3);
    expect(appFiles).toEqual([
      { path: "bbb/ccc/y.js" },
      { path: "bbb/ccc/z.js" },
      { path: "x.js" },
    ]);
  });

  it("should correctly identify node manifest files", async () => {
    const nodeProjectFiles = {
      "/srv/dist/index.js": "",
      "/srv/dist/src/app.js": "",
      "/srv/dist/src/utils/helpers.js": "",
      "/srv/dist/src/components/header.ts": "",
      "/srv/dist/src/components/footer.js": "",
      "/srv/dist/src/services/api.js": "",
      "/srv/dist/src/models/user.js": "",
      "/srv/dist/src/config/config.ts": "",
      "/srv/dist/package.json": "{}",
      "/srv/dist/package-lock.json": "{}",
    };

    const appFiles = getAppFileInfos(
      nodeProjectFiles,
      "/srv/dist",
      filesMetadataExtractorPerLanguage.node,
    );
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
      {
        path: "package.json",
        type: "Manifest",
        metadata: { moduleName: "package.json" },
      },
      {
        path: "package-lock.json",
        type: "Manifest",
        metadata: { moduleName: "package.json" },
      },
    ]);
  });

  it("should not change app files path when root dir is /", async () => {
    const nodeProjectFiles = {
      "/srv/dist/index.js": "",
      "/opt/app.js": "",
    };
    const appFiles = getAppFileInfos(
      nodeProjectFiles,
      "/",
      filesMetadataExtractorPerLanguage.node,
    );
    expect(appFiles.length).toBe(2);
    expect(appFiles).toEqual([
      { path: "srv/dist/index.js" },
      { path: "opt/app.js" },
    ]);
  });

  it("should correctly get app infos for python files", async () => {
    const pythonProjectFiles = {
      "/app/index.py": "",
      "/app/src/app.py": "",
      "/app/src/utils/helpers.py": "",
      "/app/src/components/header.py": "",
      "/app/src/components/footer.py": "",
      "/app/src/services/api.py": "",
      "/app/src/models/user.py": "",
      "/app/src/config/config.py": "",
      "/app/requirements.txt": "",
    };
    const appFiles = getAppFileInfos(
      pythonProjectFiles,
      "/app",
      filesMetadataExtractorPerLanguage.python,
    );

    expect(appFiles.length).toBe(9);
    expect(appFiles).toEqual([
      { path: "index.py" },
      { path: "src/app.py" },
      { path: "src/utils/helpers.py" },
      { path: "src/components/header.py" },
      { path: "src/components/footer.py" },
      { path: "src/services/api.py" },
      { path: "src/models/user.py" },
      { path: "src/config/config.py" },
      { path: "requirements.txt" },
    ]);
  });
});
