import { analyze } from "../../../../../lib/analyzer/package-sources/package-managers/chisel";
import { AnalysisType, ChiselPackage } from "../../../../../lib/analyzer/types";

describe("chisel analyzer", () => {
  describe("analyze()", () => {
    it("returns empty analysis for empty package list", async () => {
      const result = await analyze("test-image", []);

      expect(result).toEqual({
        Image: "test-image",
        AnalyzeType: AnalysisType.Chisel,
        Analysis: [],
      });
    });

    it("converts single Chisel package to analyzed format", async () => {
      const chiselPackages: ChiselPackage[] = [
        {
          kind: "package",
          name: "base-files",
          version: "13.6ubuntu2",
          sha256:
            "301da02c1fa60d35714c289627b8cf5c0616c16acf6cb35b0c048b107f9f1460",
          arch: "arm64",
        },
      ];

      const result = await analyze("ubuntu/python:3.13", chiselPackages);

      expect(result).toEqual({
        Image: "ubuntu/python:3.13",
        AnalyzeType: AnalysisType.Chisel,
        Analysis: [
          {
            Name: "base-files",
            Version: "13.6ubuntu2",
            Source: undefined,
            Provides: [],
            Deps: {},
            AutoInstalled: undefined,
          },
        ],
      });
    });

    it("converts multiple Chisel packages to analyzed format", async () => {
      const chiselPackages: ChiselPackage[] = [
        {
          kind: "package",
          name: "base-files",
          version: "13.6ubuntu2",
          sha256: "abc123",
          arch: "arm64",
        },
        {
          kind: "package",
          name: "ca-certificates",
          version: "20241223",
          sha256: "def456",
          arch: "all",
        },
        {
          kind: "package",
          name: "libc6",
          version: "2.41-6ubuntu1.2",
          sha256: "ghi789",
          arch: "arm64",
        },
      ];

      const result = await analyze("test-image", chiselPackages);

      expect(result.Analysis).toHaveLength(3);
      expect(result.AnalyzeType).toBe(AnalysisType.Chisel);
    });

    it("sets all optional fields to appropriate defaults", async () => {
      const chiselPackages: ChiselPackage[] = [
        {
          kind: "package",
          name: "test-pkg",
          version: "1.0",
          sha256: "test-sha",
          arch: "arm64",
        },
      ];

      const result = await analyze("test-image", chiselPackages);

      const analyzedPkg = result.Analysis[0];
      expect(analyzedPkg.Source).toBeUndefined();
      expect(analyzedPkg.Provides).toEqual([]);
      expect(analyzedPkg.Deps).toEqual({});
      expect(analyzedPkg.AutoInstalled).toBeUndefined();
    });
  });
});
