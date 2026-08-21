jest.mock("../../../lib/extractor", () => {
  const actual = jest.requireActual("../../../lib/extractor");
  return {
    ...actual,
    extractImageContent: jest.fn(),
  };
});

import { extractImageContent } from "../../../lib/extractor";
import { getSwiftAppFileContentAction } from "../../../lib/inputs/swift/static";
import { ImageType } from "../../../lib/types";
import { analyze } from "../../../lib/analyzer/static-analyzer";

const mockExtractImageContent = extractImageContent as jest.Mock;

describe("Swift wiring in static-analyzer", () => {
  afterEach(() => {
    mockExtractImageContent.mockReset();
  });

  it("registers the Swift extract action for extraction", async () => {
    mockExtractImageContent.mockResolvedValue({
      imageId: "sha256:fake",
      manifestLayers: [],
      extractedLayers: {},
    });

    await analyze(
      "test-image",
      undefined,
      ImageType.DockerArchive,
      "/fake/path",
      { include: [], exclude: [] },
      {},
    );

    const [, , staticAnalysisActions] = mockExtractImageContent.mock.calls[0];
    expect(staticAnalysisActions).toContain(getSwiftAppFileContentAction);
  });

  it("does not register the Swift extract action when app-vuln scanning is excluded", async () => {
    mockExtractImageContent.mockResolvedValue({
      imageId: "sha256:fake",
      manifestLayers: [],
      extractedLayers: {},
    });

    await analyze(
      "test-image",
      undefined,
      ImageType.DockerArchive,
      "/fake/path",
      { include: [], exclude: [] },
      { "exclude-app-vulns": true },
    );

    const [, , staticAnalysisActions] = mockExtractImageContent.mock.calls[0];
    expect(staticAnalysisActions).not.toContain(getSwiftAppFileContentAction);
  });

  it("collects a Package.resolved found during extraction into the scan results", async () => {
    const packageResolved = JSON.stringify({
      version: 2,
      pins: [
        {
          identity: "swift-log",
          location: "https://github.com/apple/swift-log.git",
          state: { version: "1.5.4" },
        },
      ],
    });

    mockExtractImageContent.mockResolvedValue({
      imageId: "sha256:fake",
      manifestLayers: [],
      extractedLayers: {
        "/app/Package.resolved": {
          [getSwiftAppFileContentAction.actionName]: packageResolved,
        },
      },
    });

    const result = await analyze(
      "test-image",
      undefined,
      ImageType.DockerArchive,
      "/fake/path",
      { include: [], exclude: [] },
      {},
    );

    const swiftResult = result.applicationDependenciesScanResults.find(
      (r) => r.identity.type === "swift",
    );
    expect(swiftResult).toBeDefined();
    expect(swiftResult!.identity.targetFile).toBe("/app/Package.resolved");
    expect(result.timings.swiftAnalysisMs).toBeDefined();
  });

  it("does not collect Package.resolved when app-vuln scanning is excluded", async () => {
    const packageResolved = JSON.stringify({
      version: 2,
      pins: [
        {
          identity: "swift-log",
          location: "https://github.com/apple/swift-log.git",
          state: { version: "1.5.4" },
        },
      ],
    });

    mockExtractImageContent.mockResolvedValue({
      imageId: "sha256:fake",
      manifestLayers: [],
      extractedLayers: {
        "/app/Package.resolved": {
          [getSwiftAppFileContentAction.actionName]: packageResolved,
        },
      },
    });

    const result = await analyze(
      "test-image",
      undefined,
      ImageType.DockerArchive,
      "/fake/path",
      { include: [], exclude: [] },
      { "exclude-app-vulns": true },
    );

    expect(result.applicationDependenciesScanResults).toHaveLength(0);
  });
});
