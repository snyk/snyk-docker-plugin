import { analyze } from "../../../../lib/analyzer/package-managers/spdx";
import { AnalysisType } from "../../../../lib/analyzer/types";
import { getTextFromFixture } from "../../../util";

describe("SPDX analyzer", () => {
  describe("analyze()", () => {
    it("parses single SPDX file content", async () => {
      const spdxFileContents = [
        getTextFromFixture("sbom/simple/spdx.pkg-binutils.json"),
      ];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Image).toBe("test-image");
      expect(result.AnalyzeType).toBe(AnalysisType.Spdx);
      expect(result.Analysis).toHaveLength(1);
      expect(result.Analysis[0]).toMatchObject({
        Name: "pkg-binutils", // "dhi/" prefix stripped
        Version: "2.45-debian13",
      });
    });

    it("parses multiple SPDX file contents", async () => {
      const spdxFileContents = [
        getTextFromFixture("sbom/simple/spdx.pkg-binutils.json"),
        getTextFromFixture("sbom/simple/spdx.python.json"),
      ];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis).toHaveLength(2);
      expect(result.Analysis[0].Name).toBe("pkg-binutils");
      expect(result.Analysis[1].Name).toBe("python");
    });

    it("extracts PURL from externalRefs when present", async () => {
      const spdxFileContents = [
        getTextFromFixture("sbom/simple/spdx.pkg-binutils.json"),
      ];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis[0].Purl).toBe(
        "pkg:docker/dhi/pkg-binutils@2.45-debian13?platform=linux%2Farm64&os_name=debian&os_version=13",
      );
    });

    it("creates dhi PURL when externalRefs is missing", async () => {
      const spdxFileContents = [
        JSON.stringify({
          spdxVersion: "SPDX-2.3",
          packages: [
            {
              name: "dhi/curl",
              versionInfo: "7.88.1",
              // No externalRefs
            },
          ],
        }),
      ];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis[0].Purl).toBe("pkg:dhi/curl@7.88.1");
    });

    it("handles malformed SPDX gracefully", async () => {
      const spdxFileContents = [
        getTextFromFixture("sbom/simple/spdx.malformed.json"),
        getTextFromFixture("sbom/simple/spdx.python.json"),
      ];

      const result = await analyze("test-image", spdxFileContents);

      // Should skip broken file but process valid one
      expect(result.Analysis).toHaveLength(1);
      expect(result.Analysis[0].Name).toBe("python");
    });

    it("handles SPDX with no packages array", async () => {
      const spdxFileContents = [JSON.stringify({ spdxVersion: "SPDX-2.3" })];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis).toHaveLength(0);
    });

    it("strips 'dhi/' prefix from package names", async () => {
      const spdxFileContents = [
        JSON.stringify({
          spdxVersion: "SPDX-2.3",
          packages: [
            {
              name: "dhi/my-package",
              versionInfo: "1.0.0",
            },
          ],
        }),
      ];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis[0].Name).toBe("my-package");
      expect(result.Analysis[0].Name).not.toContain("dhi/");
    });

    it("handles empty array of SPDX files", async () => {
      const spdxFileContents: string[] = [];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis).toHaveLength(0);
    });

    it("sets all standard package fields", async () => {
      const spdxFileContents = [
        JSON.stringify({
          spdxVersion: "SPDX-2.3",
          packages: [
            {
              name: "dhi/test-pkg",
              versionInfo: "1.0.0",
            },
          ],
        }),
      ];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis[0]).toEqual({
        Name: "test-pkg",
        Version: "1.0.0",
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
        Purl: "pkg:dhi/test-pkg@1.0.0",
      });
    });

    it("processes packages from multiple SPDX files in order", async () => {
      const spdxFileContents = [
        JSON.stringify({
          spdxVersion: "SPDX-2.3",
          packages: [
            { name: "dhi/first", versionInfo: "1.0.0" },
            { name: "dhi/second", versionInfo: "2.0.0" },
          ],
        }),
        JSON.stringify({
          spdxVersion: "SPDX-2.3",
          packages: [{ name: "dhi/third", versionInfo: "3.0.0" }],
        }),
      ];

      const result = await analyze("test-image", spdxFileContents);

      expect(result.Analysis).toHaveLength(3);
      expect(result.Analysis[0].Name).toBe("first");
      expect(result.Analysis[1].Name).toBe("second");
      expect(result.Analysis[2].Name).toBe("third");
    });
  });
});
