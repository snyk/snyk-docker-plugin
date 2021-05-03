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
