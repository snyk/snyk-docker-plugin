import * as fs from "fs";
import * as path from "path";
import { extractImageLayer } from "../../../lib/extractor/layer";
import { ExtractAction } from "../../../lib/extractor/types";
import { getGoModulesContentAction } from "../../../lib/go-parser";
const getFixture = (fixturePath) =>
  path.join(__dirname, "../../fixtures", fixturePath);

describe("layer extractor: layer contain bad elf file", () => {
  it("it should return empty file object", () => {
    const staticAnalysisActions: ExtractAction[] = [];
    staticAnalysisActions.push(...[getGoModulesContentAction]);
    const stream = fs.createReadStream(
      getFixture("extracted-layers/layer_with_bad_elf_file.tar"),
    );
    const p = extractImageLayer(stream, staticAnalysisActions);
    expect(p).toMatchObject({});
  });
});

describe("layer extractor: layer contain cgo compiled go file", () => {
  it("it should return empty file object", () => {
    const staticAnalysisActions: ExtractAction[] = [];
    staticAnalysisActions.push(...[getGoModulesContentAction]);
    const stream = fs.createReadStream(
      getFixture("extracted-layers/cgo-compiled-file.tar"),
    );
    const p = extractImageLayer(stream, staticAnalysisActions);
    expect(p).toMatchObject({});
  });
});

describe("layer extractor: POSIX path normalization fix", () => {
  it("should use path.posix.join to normalize file paths for Windows compatibility", async () => {
    const capturedPaths: string[] = [];
    const mockExtractAction: ExtractAction = {
      actionName: "posix-path-test",
      filePathMatches: (filePath: string) => {
        capturedPaths.push(filePath);
        return false;
      },
    };

    const stream = fs.createReadStream(
      getFixture("docker-archives/docker-save/go-binaries.tar"),
    );
    await extractImageLayer(stream, [mockExtractAction]);

    expect(capturedPaths.length).toBeGreaterThan(0);
    capturedPaths.forEach((filePath) => {
      expect(filePath.startsWith("/")).toBe(true);
      expect(filePath).not.toContain("\\");
      expect(path.posix.isAbsolute(filePath)).toBe(true);
    });
  });
});
