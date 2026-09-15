import * as fs from "fs";
import * as path from "path";
import { rustFilesToScannedProjects } from "../../../../lib/analyzer/applications/rust";
import { getFileContent } from "../../../../lib/inputs";
import { getRustAppFileContentAction } from "../../../../lib/inputs/rust/static";
import { ExtractedLayers } from "../../../../lib/extractor/types";

const fixturesPath = path.join(__dirname, "../../../fixtures/rust/simple");

function buildExtractedLayers(
  filePathToContent: Record<string, string>,
): ExtractedLayers {
  const extractedLayers: ExtractedLayers = {};
  const actionName = getRustAppFileContentAction.actionName;

  for (const [filePath, content] of Object.entries(filePathToContent)) {
    extractedLayers[filePath] = {
      [actionName]: content,
    };
  }

  return extractedLayers;
}

describe("rust extracted layers integration", () => {
  it("produces a cargo scan result from synthetic extracted layers", async () => {
    const lockContent = fs.readFileSync(
      path.join(fixturesPath, "Cargo.lock"),
      "utf-8",
    );
    const manifestContent = fs.readFileSync(
      path.join(fixturesPath, "Cargo.toml"),
      "utf-8",
    );

    const extractedLayers = buildExtractedLayers({
      "/app/Cargo.lock": lockContent,
      "/app/Cargo.toml": manifestContent,
    });

    const filePathToContent = getFileContent(
      extractedLayers,
      getRustAppFileContentAction.actionName,
    );
    const results = await rustFilesToScannedProjects(filePathToContent);

    expect(results).toHaveLength(1);
    expect(results[0].identity.type).toBe("cargo");

    const depGraph = results[0].facts.find((f) => f.type === "depGraph")!.data;
    expect(depGraph.getPkgs().length).toBeGreaterThan(0);
  });
});
