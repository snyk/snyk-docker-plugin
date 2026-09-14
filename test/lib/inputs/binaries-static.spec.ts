import {
  getBinariesHashes,
  getDotnetBinariesFileContentAction,
  getNodeBinariesFileContentAction,
  getOpenJDKBinariesFileContentAction,
} from "../../../lib/inputs/binaries/static";
import { ExtractedLayers } from "../../../lib/extractor/types";

describe("getDotnetBinariesFileContentAction.filePathMatches", () => {
  const matches = getDotnetBinariesFileContentAction.filePathMatches!;

  it("has the expected action name", () => {
    expect(getDotnetBinariesFileContentAction.actionName).toBe("dotnet");
  });

  it("matches libcoreclr.so under the shared framework path", () => {
    expect(
      matches(
        "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.1/libcoreclr.so",
      ),
    ).toBe(true);
  });

  it("matches System.Private.CoreLib.dll under the shared framework path", () => {
    expect(
      matches(
        "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.1/System.Private.CoreLib.dll",
      ),
    ).toBe(true);
  });

  it("matches on win32-style backslash paths", () => {
    expect(
      matches("\\dotnet\\shared\\Microsoft.NETCore.App\\8.0.1\\libcoreclr.so"),
    ).toBe(true);
  });

  it("does not match a same-named file outside the shared framework path", () => {
    expect(matches("/app/libcoreclr.so")).toBe(false);
  });

  it("does not match a same-named file under a self-contained app layout", () => {
    expect(
      matches("/app/bin/Release/net8.0/linux-x64/publish/libcoreclr.so"),
    ).toBe(false);
  });

  it("does not match Microsoft.AspNetCore.App (no CLR host shipped there)", () => {
    expect(
      matches(
        "/usr/share/dotnet/shared/Microsoft.AspNetCore.App/8.0.1/libcoreclr.so",
      ),
    ).toBe(false);
  });

  it("does not match other files under the shared framework path", () => {
    expect(
      matches(
        "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.1/System.Runtime.dll",
      ),
    ).toBe(false);
  });

  it("does not match an empty string", () => {
    expect(matches("")).toBe(false);
  });
});

describe("getBinariesHashes", () => {
  function makeLayer(
    filePath: string,
    actionName: string,
    hash: string,
  ): ExtractedLayers {
    return { [filePath]: { [actionName]: hash } };
  }

  it("includes a dotnet key binary hash in the flat result", () => {
    const layers = makeLayer(
      "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.1/libcoreclr.so",
      "dotnet",
      "dotnet-hash",
    );
    expect(getBinariesHashes(layers)).toEqual(["dotnet-hash"]);
  });

  it("still includes node key binary hashes (non-regression)", () => {
    expect(getNodeBinariesFileContentAction.actionName).toBe("node");
    const layers = makeLayer("/usr/local/bin/node", "node", "node-hash");
    expect(getBinariesHashes(layers)).toEqual(["node-hash"]);
  });

  it("still includes java key binary hashes (non-regression)", () => {
    expect(getOpenJDKBinariesFileContentAction.actionName).toBe("java");
    const layers = makeLayer(
      "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
      "java",
      "java-hash",
    );
    expect(getBinariesHashes(layers)).toEqual(["java-hash"]);
  });

  it("dedupes identical hashes across actions", () => {
    const layers: ExtractedLayers = {
      "/usr/local/bin/node": { node: "same-hash" },
      "/usr/lib/jvm/java-17-openjdk-amd64/bin/java": { java: "same-hash" },
    };
    expect(getBinariesHashes(layers)).toEqual(["same-hash"]);
  });

  it("combines node, java, and dotnet hashes from multiple layers", () => {
    const layers: ExtractedLayers = {
      "/usr/local/bin/node": { node: "node-hash" },
      "/usr/lib/jvm/java-17-openjdk-amd64/bin/java": { java: "java-hash" },
      "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.1/libcoreclr.so": {
        dotnet: "dotnet-hash",
      },
    };
    expect(getBinariesHashes(layers).sort()).toEqual(
      ["dotnet-hash", "java-hash", "node-hash"].sort(),
    );
  });
});
