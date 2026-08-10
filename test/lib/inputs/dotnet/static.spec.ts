import { getDotnetAppFileContentAction } from "../../../../lib/inputs/dotnet/static";
import { streamToString } from "../../../../lib/stream-utils";

describe(".NET application file path matching", () => {
  const { filePathMatches, actionName, callback } =
    getDotnetAppFileContentAction;

  it("exports getDotnetAppFileContentAction with expected actionName and callback", () => {
    expect(actionName).toBe("dotnet-app-files");
    expect(callback).toBe(streamToString);
  });

  describe("application manifest paths (forward slashes)", () => {
    it.each([
      "/app/packages.config",
      "/app/App.csproj",
      "/app/App.fsproj",
      "/app/App.vbproj",
      "/app/obj/project.assets.json",
      "/app/packages.lock.json",
      "/app/App.deps.json",
    ])("matches %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(true);
    });
  });

  describe("application manifest paths (backslashes)", () => {
    it.each([
      "\\app\\packages.config",
      "\\app\\App.csproj",
      "\\app\\App.fsproj",
      "\\app\\App.vbproj",
      "\\app\\obj\\project.assets.json",
      "\\app\\packages.lock.json",
      "\\app\\App.deps.json",
    ])("matches %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(true);
    });
  });

  describe("framework, SDK, and cache paths (forward slashes)", () => {
    it.each([
      "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.0/x.deps.json",
      "/usr/share/dotnet/packs/x.deps.json",
      "/usr/share/dotnet/sdk/8.0.100/x.csproj",
      "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.0/x.csproj",
      "/root/.nuget/packages/foo/1.0.0/contentFiles/any/net8.0/x.csproj",
      "/app/project.assets.json",
      "/app/foo.json",
    ])("does not match %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(false);
    });
  });

  describe("framework, SDK, and cache paths (backslashes)", () => {
    it.each([
      "\\usr\\share\\dotnet\\shared\\Microsoft.NETCore.App\\8.0.0\\x.deps.json",
      "\\usr\\share\\dotnet\\packs\\x.deps.json",
      "\\root\\.nuget\\packages\\foo\\1.0.0\\contentFiles\\any\\net8.0\\x.csproj",
    ])("does not match %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(false);
    });
  });
});
