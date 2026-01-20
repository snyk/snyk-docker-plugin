import { parseAnalysisResults } from "../../../lib/parser/index";
import { AnalysisType, StaticPackagesAnalysis } from "../../../lib/analyzer/types";

describe("parseAnalysisResults", () => {
  const mockOSRelease = {
    name: "debian",
    version: "12",
    prettyName: "Debian GNU/Linux 12 (bookworm)",
  };

  describe("SPDX deduplication", () => {
    it("should include SPDX packages when there are no conflicts with apt packages", () => {
      const analysis: StaticPackagesAnalysis = {
        imageId: "test-image-123",
        platform: "linux/amd64",
        osRelease: mockOSRelease,
        results: [
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Apt,
            Analysis: [
              {
                Name: "curl",
                Version: "7.88.1-10+deb12u8",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:deb/debian/curl@7.88.1-10+deb12u8",
              },
            ],
          },
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Spdx,
            Analysis: [
              {
                Name: "python",
                Version: "3.11.2",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/python@3.11.2",
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: ["layer1", "layer2"],
        applicationDependenciesScanResults: [],
        manifestFiles: [],
      };

      const result = parseAnalysisResults("test-image", analysis);

      // Should include both apt and SPDX packages since there's no conflict
      expect(result.depInfosList).toHaveLength(2);
      expect(result.depInfosList[0].Name).toBe("curl");
      expect(result.depInfosList[0].Purl).toBe("pkg:deb/debian/curl@7.88.1-10+deb12u8");
      expect(result.depInfosList[1].Name).toBe("python");
      expect(result.depInfosList[1].Purl).toBe("pkg:dhi/python@3.11.2");
    });

    it("should prioritize apt packages over SPDX when there are duplicate names", () => {
      const analysis: StaticPackagesAnalysis = {
        imageId: "test-image-123",
        platform: "linux/amd64",
        osRelease: mockOSRelease,
        results: [
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Apt,
            Analysis: [
              {
                Name: "curl",
                Version: "7.88.1-10+deb12u8",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:deb/debian/curl@7.88.1-10+deb12u8",
              },
              {
                Name: "python",
                Version: "3.11.2-1+deb12u4",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:deb/debian/python@3.11.2-1+deb12u4",
              },
            ],
          },
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Spdx,
            Analysis: [
              {
                Name: "python",
                Version: "3.11.2",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/python@3.11.2",
              },
              {
                Name: "redis-server",
                Version: "7.0.15",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/redis-server@7.0.15",
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: ["layer1", "layer2"],
        applicationDependenciesScanResults: [],
        manifestFiles: [],
      };

      const result = parseAnalysisResults("test-image", analysis);

      // Should have 3 packages: curl and python from apt, redis-server from SPDX
      expect(result.depInfosList).toHaveLength(3);
      
      // Find each package
      const curlPkg = result.depInfosList.find((pkg) => pkg.Name === "curl");
      const pythonPkg = result.depInfosList.find((pkg) => pkg.Name === "python");
      const redisPkg = result.depInfosList.find((pkg) => pkg.Name === "redis-server");

      // Verify curl from apt
      expect(curlPkg).toBeDefined();
      expect(curlPkg?.Version).toBe("7.88.1-10+deb12u8");
      expect(curlPkg?.Purl).toBe("pkg:deb/debian/curl@7.88.1-10+deb12u8");

      // Verify python from apt (NOT from SPDX - apt takes precedence)
      expect(pythonPkg).toBeDefined();
      expect(pythonPkg?.Version).toBe("3.11.2-1+deb12u4");
      expect(pythonPkg?.Purl).toBe("pkg:deb/debian/python@3.11.2-1+deb12u4");
      expect(pythonPkg?.Purl).not.toContain("dhi");

      // Verify redis-server from SPDX (no conflict)
      expect(redisPkg).toBeDefined();
      expect(redisPkg?.Version).toBe("7.0.15");
      expect(redisPkg?.Purl).toBe("pkg:dhi/redis-server@7.0.15");
    });

    it("should prioritize apk packages over SPDX when there are duplicate names", () => {
      const analysis: StaticPackagesAnalysis = {
        imageId: "test-image-123",
        platform: "linux/arm64",
        osRelease: { name: "alpine", version: "3.19", prettyName: "Alpine Linux 3.19" },
        results: [
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Apk,
            Analysis: [
              {
                Name: "curl",
                Version: "8.5.0-r0",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:apk/alpine/curl@8.5.0-r0",
              },
            ],
          },
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Spdx,
            Analysis: [
              {
                Name: "curl",
                Version: "8.5.0",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/curl@8.5.0",
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: ["layer1"],
        applicationDependenciesScanResults: [],
        manifestFiles: [],
      };

      const result = parseAnalysisResults("test-image", analysis);

      // Should only have curl from apk, not from SPDX
      expect(result.depInfosList).toHaveLength(1);
      expect(result.depInfosList[0].Name).toBe("curl");
      expect(result.depInfosList[0].Version).toBe("8.5.0-r0");
      expect(result.depInfosList[0].Purl).toBe("pkg:apk/alpine/curl@8.5.0-r0");
    });

    it("should work when there are only SPDX packages (no apt/apk)", () => {
      const analysis: StaticPackagesAnalysis = {
        imageId: "test-image-123",
        platform: "linux/arm64",
        osRelease: mockOSRelease,
        results: [
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Apt,
            Analysis: [],
          },
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Spdx,
            Analysis: [
              {
                Name: "python",
                Version: "3.11.2",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/python@3.11.2",
              },
              {
                Name: "redis-server",
                Version: "7.0.15",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/redis-server@7.0.15",
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: ["layer1"],
        applicationDependenciesScanResults: [],
        manifestFiles: [],
      };

      const result = parseAnalysisResults("test-image", analysis);

      // Should have both SPDX packages
      expect(result.depInfosList).toHaveLength(2);
      expect(result.depInfosList[0].Name).toBe("python");
      expect(result.depInfosList[1].Name).toBe("redis-server");
    });

    it("should prioritize rpm packages over SPDX when there are duplicate names", () => {
      const analysis: StaticPackagesAnalysis = {
        imageId: "test-image-123",
        platform: "linux/amd64",
        osRelease: { name: "rhel", version: "9", prettyName: "Red Hat Enterprise Linux 9" },
        results: [
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Rpm,
            Analysis: [
              {
                Name: "openssl",
                Version: "3.0.7-27.el9",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:rpm/rhel/openssl@3.0.7-27.el9",
              },
            ],
          },
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Spdx,
            Analysis: [
              {
                Name: "openssl",
                Version: "3.0.7",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/openssl@3.0.7",
              },
              {
                Name: "nginx",
                Version: "1.24.0",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/nginx@1.24.0",
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: ["layer1"],
        applicationDependenciesScanResults: [],
        manifestFiles: [],
      };

      const result = parseAnalysisResults("test-image", analysis);

      // Should have 2 packages: openssl from rpm, nginx from SPDX
      expect(result.depInfosList).toHaveLength(2);
      
      const opensslPkg = result.depInfosList.find((pkg) => pkg.Name === "openssl");
      const nginxPkg = result.depInfosList.find((pkg) => pkg.Name === "nginx");

      // Verify openssl from rpm (NOT from SPDX)
      expect(opensslPkg).toBeDefined();
      expect(opensslPkg?.Version).toBe("3.0.7-27.el9");
      expect(opensslPkg?.Purl).toBe("pkg:rpm/rhel/openssl@3.0.7-27.el9");

      // Verify nginx from SPDX (no conflict)
      expect(nginxPkg).toBeDefined();
      expect(nginxPkg?.Purl).toBe("pkg:dhi/nginx@1.24.0");
    });

    it("should prioritize chisel packages over SPDX when there are duplicate names", () => {
      const analysis: StaticPackagesAnalysis = {
        imageId: "test-image-123",
        platform: "linux/amd64",
        osRelease: mockOSRelease,
        results: [
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Chisel,
            Analysis: [
              {
                Name: "base-files",
                Version: "12.3ubuntu1",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:deb/ubuntu/base-files@12.3ubuntu1",
              },
            ],
          },
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Spdx,
            Analysis: [
              {
                Name: "base-files",
                Version: "12.3",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/base-files@12.3",
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: ["layer1"],
        applicationDependenciesScanResults: [],
        manifestFiles: [],
      };

      const result = parseAnalysisResults("test-image", analysis);

      // Should only have base-files from chisel, not from SPDX
      expect(result.depInfosList).toHaveLength(1);
      expect(result.depInfosList[0].Name).toBe("base-files");
      expect(result.depInfosList[0].Version).toBe("12.3ubuntu1");
      expect(result.depInfosList[0].Purl).toBe("pkg:deb/ubuntu/base-files@12.3ubuntu1");
    });

    it("should handle multiple duplicate packages between apt and SPDX", () => {
      const analysis: StaticPackagesAnalysis = {
        imageId: "test-image-123",
        platform: "linux/amd64",
        osRelease: mockOSRelease,
        results: [
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Apt,
            Analysis: [
              {
                Name: "curl",
                Version: "7.88.1-10+deb12u8",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:deb/debian/curl@7.88.1-10+deb12u8",
              },
              {
                Name: "wget",
                Version: "1.21.3-1+b2",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:deb/debian/wget@1.21.3-1+b2",
              },
            ],
          },
          {
            Image: "test-image",
            AnalyzeType: AnalysisType.Spdx,
            Analysis: [
              {
                Name: "curl",
                Version: "7.88.1",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/curl@7.88.1",
              },
              {
                Name: "wget",
                Version: "1.21.3",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/wget@1.21.3",
              },
              {
                Name: "redis-tools",
                Version: "7.0.15",
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
                Purl: "pkg:dhi/redis-tools@7.0.15",
              },
            ],
          },
        ],
        binaries: [],
        imageLayers: ["layer1", "layer2"],
        applicationDependenciesScanResults: [],
        manifestFiles: [],
      };

      const result = parseAnalysisResults("test-image", analysis);

      // Should have 3 packages total: curl and wget from apt, redis-tools from SPDX
      expect(result.depInfosList).toHaveLength(3);
      
      const curlPkg = result.depInfosList.find((pkg) => pkg.Name === "curl");
      const wgetPkg = result.depInfosList.find((pkg) => pkg.Name === "wget");
      const redisPkg = result.depInfosList.find((pkg) => pkg.Name === "redis-tools");

      // Verify all packages from apt (NOT from SPDX)
      expect(curlPkg?.Purl).toBe("pkg:deb/debian/curl@7.88.1-10+deb12u8");
      expect(wgetPkg?.Purl).toBe("pkg:deb/debian/wget@1.21.3-1+b2");
      
      // Verify redis-tools from SPDX (no conflict)
      expect(redisPkg?.Purl).toBe("pkg:dhi/redis-tools@7.0.15");
    });
  });
});

