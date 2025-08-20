import { poetryFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { FilePathToContent } from "../../../lib/analyzer/applications/types";

// Mock the lockfile parser
jest.mock("snyk-poetry-lockfile-parser", () => ({
  buildDepGraph: jest.fn(),
}));

import * as lockFileParser from "snyk-poetry-lockfile-parser";

describe("poetry analyzer", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("correctly creates a dep graph from pyproject.toml and poetry.lock", async () => {
    const mockDepGraph = {
      pkgManager: { name: "poetry" },
      rootPkg: { name: "test-project", version: "1.0.0" },
      depPkgsList: [{ name: "flask", version: "2.0.0" }],
    };

    (lockFileParser.buildDepGraph as jest.Mock).mockResolvedValue(mockDepGraph);

    const filePathToContent: FilePathToContent = {
      "/app/pyproject.toml": `[tool.poetry]
name = "test-project"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.8"
flask = "^2.0.0"`,
      "/app/poetry.lock": `[[package]]
name = "flask"
version = "2.0.0"`,
    };

    const res = await poetryFilesToScannedProjects(filePathToContent);

    expect(res).toHaveLength(1);
    expect(res[0].identity).toMatchObject({
      type: "poetry",
      targetFile: "/app/pyproject.toml",
    });
    expect(res[0].facts[0].type).toBe("depGraph");
    expect(res[0].facts[0].data).toBe(mockDepGraph);
    expect(res[0].facts[1].type).toBe("testedFiles");
    expect(res[0].facts[1].data).toEqual(["pyproject.toml", "poetry.lock"]);
  });

  it("handles when buildDepGraph returns null", async () => {
    // This tests the uncovered branch when depGraph is falsy
    (lockFileParser.buildDepGraph as jest.Mock).mockResolvedValue(null);

    const filePathToContent: FilePathToContent = {
      "/app/pyproject.toml": `[tool.poetry]
name = "test-project"
version = "1.0.0"`,
      "/app/poetry.lock": `[[package]]
name = "flask"
version = "2.0.0"`,
    };

    const res = await poetryFilesToScannedProjects(filePathToContent);

    // Should return empty array when depGraph is null
    expect(res).toHaveLength(0);
    expect(lockFileParser.buildDepGraph).toHaveBeenCalledWith(
      filePathToContent["/app/pyproject.toml"],
      filePathToContent["/app/poetry.lock"],
      false,
    );
  });

  it("handles multiple poetry projects in different directories", async () => {
    const mockDepGraph1 = {
      pkgManager: { name: "poetry" },
      rootPkg: { name: "project1", version: "1.0.0" },
    };
    const mockDepGraph2 = {
      pkgManager: { name: "poetry" },
      rootPkg: { name: "project2", version: "2.0.0" },
    };

    (lockFileParser.buildDepGraph as jest.Mock)
      .mockResolvedValueOnce(mockDepGraph1)
      .mockResolvedValueOnce(mockDepGraph2);

    const filePathToContent: FilePathToContent = {
      "/app1/pyproject.toml": `[tool.poetry]
name = "project1"`,
      "/app1/poetry.lock": `[[package]]`,
      "/app2/pyproject.toml": `[tool.poetry]
name = "project2"`,
      "/app2/poetry.lock": `[[package]]`,
    };

    const res = await poetryFilesToScannedProjects(filePathToContent);

    expect(res).toHaveLength(2);
    expect(res[0].identity.targetFile).toBe("/app1/pyproject.toml");
    expect(res[1].identity.targetFile).toBe("/app2/pyproject.toml");
  });

  it("ignores directories without both manifest and lock files", async () => {
    const filePathToContent: FilePathToContent = {
      // Only has pyproject.toml, missing poetry.lock
      "/app1/pyproject.toml": `[tool.poetry]`,
      // Only has poetry.lock, missing pyproject.toml
      "/app2/poetry.lock": `[[package]]`,
      // Has both files
      "/app3/pyproject.toml": `[tool.poetry]`,
      "/app3/poetry.lock": `[[package]]`,
    };

    const mockDepGraph = {
      pkgManager: { name: "poetry" },
      rootPkg: { name: "project3", version: "1.0.0" },
    };

    (lockFileParser.buildDepGraph as jest.Mock).mockResolvedValue(mockDepGraph);

    const res = await poetryFilesToScannedProjects(filePathToContent);

    // Should only process app3 which has both files
    expect(res).toHaveLength(1);
    expect(res[0].identity.targetFile).toBe("/app3/pyproject.toml");
  });

  it("ignores directories with too many files", async () => {
    const filePathToContent: FilePathToContent = {
      // Directory with more than 2 files
      "/app/pyproject.toml": `[tool.poetry]`,
      "/app/poetry.lock": `[[package]]`,
      "/app/extra.txt": "extra file",
    };

    const res = await poetryFilesToScannedProjects(filePathToContent);

    // Should return empty array as the directory has too many files
    expect(res).toHaveLength(0);
    expect(lockFileParser.buildDepGraph).not.toHaveBeenCalled();
  });
});
