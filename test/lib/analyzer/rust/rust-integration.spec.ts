import * as fs from "fs";
import * as path from "path";

import { cargoFilesToScannedProjects } from "../../../../lib/analyzer/applications/rust/cargo";
import { ExtractedLayers } from "../../../../lib/extractor/types";
import { getFileContent } from "../../../../lib/inputs";
import { getRustAppFileContentAction } from "../../../../lib/inputs/rust/static";

const cargoLockContent = fs.readFileSync(
  path.join(__dirname, "../../../fixtures/rust/v3/Cargo.lock"),
  "utf-8",
);

describe("Rust static analyzer integration", () => {
  it("retrieves Cargo.lock via rust-app-files and produces a cargo scan result", async () => {
    const extractedLayers: ExtractedLayers = {
      "/app/Cargo.lock": {
        "rust-app-files": cargoLockContent,
      },
      "/app/index.js": {
        "node-app-files": "",
      },
    };

    const cargoLockFiles = getFileContent(
      extractedLayers,
      getRustAppFileContentAction.actionName,
    );

    expect(Object.keys(cargoLockFiles)).toEqual(["/app/Cargo.lock"]);

    const results = await cargoFilesToScannedProjects(cargoLockFiles);

    expect(results).toHaveLength(1);
    expect(results[0].identity.type).toBe("cargo");
    expect(results[0].identity.targetFile).toBe("/app/Cargo.lock");
  });
});
