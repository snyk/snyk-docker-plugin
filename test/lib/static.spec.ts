import { ImageType } from "../../lib/types";

jest.mock("../../lib/analyzer");
jest.mock("../../lib/parser");
jest.mock("../../lib/dependency-tree");
jest.mock("../../lib/response-builder");
jest.mock("../../lib/extractor/fetch-registry-provenance-attestations");

import * as analyzer from "../../lib/analyzer";
import { buildTree } from "../../lib/dependency-tree";
import { fetchAttestationsFromRegistry } from "../../lib/extractor/fetch-registry-provenance-attestations";
import { parseAnalysisResults } from "../../lib/parser";
import { buildResponse } from "../../lib/response-builder";
import { analyzeStatically } from "../../lib/static";

const mockedAnalyzer = analyzer.analyzeStatically as jest.Mock;
const mockedParse = parseAnalysisResults as jest.Mock;
const mockedBuildTree = buildTree as jest.Mock;
const mockedBuildResponse = buildResponse as jest.Mock;
const mockedFetch = fetchAttestationsFromRegistry as jest.Mock;

describe("analyzeStatically provenance registry fetch", () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // No attestations found inside the image, which is what makes the code consider
    // asking the registry for them.
    mockedAnalyzer.mockResolvedValue({ attestations: [], timings: {} });
    mockedParse.mockReturnValue({
      imageId: "sha256:abc",
      imageLayers: [],
      packageFormat: "apk",
      depInfosList: [],
      targetOS: { name: "alpine", version: "3.19", prettyName: "" },
    });
    mockedBuildTree.mockReturnValue({});
    mockedBuildResponse.mockResolvedValue({ scanResults: [] });
    mockedFetch.mockResolvedValue([]);
  });

  async function run(pulledFromRegistry?: boolean) {
    return analyzeStatically(
      "my-registry.local/app:latest",
      undefined,
      ImageType.Identifier,
      "/tmp/image.tar",
      { include: [], exclude: [] },
      {},
      undefined,
      pulledFromRegistry,
    );
  }

  it("does not call the registry for an image that was not pulled from one", async () => {
    await run(false);
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it("does not call the registry when the caller says nothing", async () => {
    // Defaulting to false keeps every existing caller on the safe side: an omitted
    // argument must not produce an outbound request.
    await run(undefined);
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it("calls the registry for an image that really was pulled from one", async () => {
    await run(true);
    expect(mockedFetch).toHaveBeenCalledTimes(1);
    expect(mockedFetch).toHaveBeenCalledWith(
      expect.objectContaining({
        registryBase: "my-registry.local",
        repo: "app",
        imageReference: "latest",
      }),
    );
  });

  it("does not call the registry when the image already carries attestations", async () => {
    mockedAnalyzer.mockResolvedValue({
      attestations: [{ some: "attestation" }],
      timings: {},
    });
    await run(true);
    expect(mockedFetch).not.toHaveBeenCalled();
  });
});
