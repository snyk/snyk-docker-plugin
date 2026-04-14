import * as fsPromises from "fs/promises";
import * as path from "path";
import { persistNodeModules } from "../../../../lib/analyzer/applications/node-modules-utils";
import {
  FilePathToContent,
  FilesByDirMap,
} from "../../../../lib/analyzer/applications/types";

// Mock fs/promises
jest.mock("fs/promises", () => ({
  mkdtemp: jest.fn(),
  mkdir: jest.fn(),
  writeFile: jest.fn(),
  stat: jest.fn(),
  rm: jest.fn(),
}));

const mockMkdtemp = fsPromises.mkdtemp as jest.MockedFunction<
  typeof fsPromises.mkdtemp
>;
const mockMkdir = fsPromises.mkdir as jest.MockedFunction<
  typeof fsPromises.mkdir
>;
const mockWriteFile = fsPromises.writeFile as jest.MockedFunction<
  typeof fsPromises.writeFile
>;
const mockStat = fsPromises.stat as jest.MockedFunction<typeof fsPromises.stat>;

describe("node-modules-utils", () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe("persistNodeModules", () => {
    const project = "my-project";

    it("should return empty paths immediately if modules set is empty or undefined", async () => {
      const fileNamesGroupedByDirectory: FilesByDirMap = new Map();
      const filePathToContent: FilePathToContent = {};

      const result = await persistNodeModules(
        project,
        filePathToContent,
        fileNamesGroupedByDirectory,
      );

      expect(result).toEqual({ tempDir: "", tempProjectPath: "" });
      expect(mockMkdtemp).not.toHaveBeenCalled();
      expect(mockMkdir).not.toHaveBeenCalled();
      expect(mockWriteFile).not.toHaveBeenCalled();
    });

    it("should successfully persist modules and return populated ScanPaths", async () => {
      const fileNamesGroupedByDirectory: FilesByDirMap = new Map();
      fileNamesGroupedByDirectory.set(project, new Set(["module1", "module2"]));

      const filePathToContent: FilePathToContent = {
        module1: "content1",
        module2: "content2",
      };

      const mockTmpDir = "/tmp/snyk-random123";
      mockMkdtemp.mockResolvedValue(mockTmpDir);
      mockMkdir.mockResolvedValue(undefined);
      mockWriteFile.mockResolvedValue(undefined);

      // Simulate that package.json exists
      mockStat.mockResolvedValue({} as any);

      const result = await persistNodeModules(
        project,
        filePathToContent,
        fileNamesGroupedByDirectory,
      );

      const expectedTempProjectPath = path.join(mockTmpDir, project);

      expect(result).toEqual({
        tempDir: mockTmpDir,
        tempProjectPath: expectedTempProjectPath,
        manifestPath: path.join(
          expectedTempProjectPath.substring(mockTmpDir.length),
          "package.json",
        ),
      });

      expect(mockMkdtemp).toHaveBeenCalledWith("snyk");
      expect(mockMkdir).toHaveBeenCalledWith(expectedTempProjectPath, {
        recursive: true,
      });
      expect(mockWriteFile).toHaveBeenCalledTimes(2); // One for each module
      // No synthetic manifest created
    });

    it("should create synthetic manifest if stat fails (package.json does not exist)", async () => {
      const fileNamesGroupedByDirectory: FilesByDirMap = new Map();
      fileNamesGroupedByDirectory.set(project, new Set(["module1"]));

      const filePathToContent: FilePathToContent = {
        module1: "content1",
      };

      const mockTmpDir = "/tmp/snyk-random123";
      mockMkdtemp.mockResolvedValue(mockTmpDir);
      mockMkdir.mockResolvedValue(undefined);
      mockWriteFile.mockResolvedValue(undefined);

      // Simulate that package.json DOES NOT exist
      mockStat.mockRejectedValue(new Error("ENOENT"));

      const result = await persistNodeModules(
        project,
        filePathToContent,
        fileNamesGroupedByDirectory,
      );

      const expectedTempProjectPath = path.join(mockTmpDir, project);

      // manifestPath is deleted from result if synthetic manifest is created
      expect(result).toEqual({
        tempDir: mockTmpDir,
        tempProjectPath: expectedTempProjectPath,
      });

      // One for module1, one for synthetic manifest
      expect(mockWriteFile).toHaveBeenCalledTimes(2);
      expect(mockWriteFile).toHaveBeenCalledWith(
        path.join(expectedTempProjectPath, "package.json"),
        "{}",
        "utf-8",
      );
    });

    it("should catch saveOnDisk failure and return populated temporary paths for cleanup (PR #788 fix)", async () => {
      const fileNamesGroupedByDirectory: FilesByDirMap = new Map();
      fileNamesGroupedByDirectory.set(project, new Set(["module1"]));

      const filePathToContent: FilePathToContent = {
        module1: "content1",
      };

      const mockTmpDir = "/tmp/snyk-random123";
      mockMkdtemp.mockResolvedValue(mockTmpDir);
      mockMkdir.mockResolvedValue(undefined);

      // Simulate a failure during saveOnDisk
      mockWriteFile.mockRejectedValue(new Error("Simulated write error"));

      const result = await persistNodeModules(
        project,
        filePathToContent,
        fileNamesGroupedByDirectory,
      );

      const expectedTempProjectPath = path.join(mockTmpDir, project);

      expect(result).toEqual({
        tempDir: mockTmpDir,
        tempProjectPath: expectedTempProjectPath,
      });
      expect(mockMkdtemp).toHaveBeenCalled();
      expect(mockMkdir).toHaveBeenCalled();
      expect(mockWriteFile).toHaveBeenCalled();
    });

    it("should catch initialization failure and return empty paths", async () => {
      const fileNamesGroupedByDirectory: FilesByDirMap = new Map();
      fileNamesGroupedByDirectory.set(project, new Set(["module1"]));

      const filePathToContent: FilePathToContent = {
        module1: "content1",
      };

      // Simulate a failure during mkdtemp (before assigning local variables)
      mockMkdtemp.mockRejectedValue(new Error("Simulated mkdtemp error"));

      const result = await persistNodeModules(
        project,
        filePathToContent,
        fileNamesGroupedByDirectory,
      );

      expect(result).toEqual({
        tempDir: "",
        tempProjectPath: "",
      });
      expect(mockMkdtemp).toHaveBeenCalled();
      expect(mockMkdir).not.toHaveBeenCalled();
      expect(mockWriteFile).not.toHaveBeenCalled();
    });
  });
});
