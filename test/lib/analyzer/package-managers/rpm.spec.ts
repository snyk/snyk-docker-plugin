import * as fs from "fs";
import * as path from "path";
import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import {
  analyze,
  mapRpmSqlitePackages,
  parseSourceRPM,
} from "../../../../lib/analyzer/package-managers/rpm";
import { SourcePackage } from "../../../../lib/analyzer/types";

describe("RPM Package Version and Epoch Handling", () => {
  describe("formats version without epoch", () => {
    it("should format version string correctly", () => {
      const mappedResults = mapRpmSqlitePackages(
        "test-image",
        [
          {
            name: "bash",
            version: "5.1.16",
            release: "4.el9",
            size: 1024,
          },
        ],
        [],
      );

      expect(mappedResults.Analysis).toHaveLength(1);
      expect(mappedResults.Analysis[0].Name).toBe("bash");
      expect(mappedResults.Analysis[0].Version).toBe("5.1.16-4.el9");
      expect(mappedResults.Analysis[0].Purl).toBe("pkg:rpm/bash@5.1.16-4.el9");
    });
  });

  describe("formats version with epoch == 0", () => {
    it("should include epoch=0 in PURL qualifier (bug fix)", () => {
      const mappedResults = mapRpmSqlitePackages(
        "test-image",
        [
          {
            name: "libarchive",
            version: "3.7.7",
            release: "4.el10_0",
            epoch: 0,
            size: 2048,
          },
        ],
        [],
      );

      expect(mappedResults.Analysis).toHaveLength(1);
      expect(mappedResults.Analysis[0].Name).toBe("libarchive");
      expect(mappedResults.Analysis[0].Version).toBe("3.7.7-4.el10_0");
      // Critical: epoch=0 must be explicitly included in PURL
      expect(mappedResults.Analysis[0].Purl).toBe(
        "pkg:rpm/libarchive@3.7.7-4.el10_0?epoch=0",
      );
    });

    it("should include epoch=0 with distro qualifier", () => {
      const mappedResults = mapRpmSqlitePackages(
        "test-image",
        [
          {
            name: "sqlite-libs",
            version: "3.34.1",
            release: "5.el8",
            epoch: 0,
            size: 1500,
          },
        ],
        [],
        { name: "rhel", version: "8.5" },
      );

      expect(mappedResults.Analysis[0].Purl).toBe(
        "pkg:rpm/rhel/sqlite-libs@3.34.1-5.el8?distro=rhel-8.5&epoch=0",
      );
    });
  });

  describe("formats version with non-zero epoch", () => {
    it("should format version with epoch=1", () => {
      const mappedResults = mapRpmSqlitePackages(
        "test-image",
        [
          {
            name: "findutils",
            version: "4.5.11",
            release: "6.amzn2",
            epoch: 1,
            size: 3000,
          },
        ],
        [],
      );

      expect(mappedResults.Analysis[0].Name).toBe("findutils");
      expect(mappedResults.Analysis[0].Version).toBe("1:4.5.11-6.amzn2");
      expect(mappedResults.Analysis[0].Purl).toBe(
        "pkg:rpm/findutils@1:4.5.11-6.amzn2?epoch=1",
      );
    });
  });

  describe("epoch consistency across functions", () => {
    it("should handle epoch=0 consistently in analyze() function", async () => {
      const pkgs: PackageInfo[] = [
        {
          name: "openssl-libs",
          version: "1.1.1",
          release: "15.el8",
          epoch: 0,
          size: 6000,
        },
      ];

      const result = await analyze(
        "test-image",
        pkgs,
        [],
        { name: "rhel", version: "8.2" },
      );

      expect(result.Analysis[0].Purl).toBe(
        "pkg:rpm/rhel/openssl-libs@1.1.1-15.el8?distro=rhel-8.2&epoch=0",
      );
    });
  });

  describe("multiple packages with different epochs", () => {
    it("should correctly handle mixed epoch values", () => {
      const packages: PackageInfo[] = [
        {
          name: "pkg-no-epoch",
          version: "1.0.0",
          release: "1",
          size: 100,
        },
        {
          name: "pkg-epoch-zero",
          version: "2.0.0",
          release: "1",
          epoch: 0,
          size: 200,
        },
        {
          name: "pkg-epoch-one",
          version: "3.0.0",
          release: "1",
          epoch: 1,
          size: 300,
        },
      ];

      const result = mapRpmSqlitePackages("test-image", packages, []);

      expect(result.Analysis[0].Purl).toBe("pkg:rpm/pkg-no-epoch@1.0.0-1");
      expect(result.Analysis[1].Purl).toBe(
        "pkg:rpm/pkg-epoch-zero@2.0.0-1?epoch=0",
      );
      expect(result.Analysis[2].Purl).toBe(
        "pkg:rpm/pkg-epoch-one@1:3.0.0-1?epoch=1",
      );
    });
  });

  describe("epoch with repositories and modules", () => {
    it("should include epoch with other qualifiers", () => {
      const result = mapRpmSqlitePackages(
        "test-image",
        [
          {
            name: "nodejs",
            version: "10.21.0",
            release: "3.module+el8.2.0",
            epoch: 1,
            module: "nodejs:10",
            size: 7000,
          },
        ],
        ["rhel-8-appstream"],
        { name: "rhel", version: "8.2" },
      );

      const purl = result.Analysis[0].Purl;
      expect(purl).toContain("?");
      expect(purl).toContain("epoch=1");
      expect(purl).toContain("module=nodejs:10");
      expect(purl).toContain("repositories=rhel-8-appstream");
      expect(purl).toContain("distro=rhel-8.2");
    });

    it("should include epoch=0 with sourceRPM upstream qualifier", () => {
      const result = mapRpmSqlitePackages(
        "test-image",
        [
          {
            name: "libxml2",
            version: "2.9.7",
            release: "14.el8",
            epoch: 0,
            sourceRPM: "libxml2-2.9.7-14.el8.src.rpm",
            size: 8000,
          },
        ],
        [],
      );

      const purl = result.Analysis[0].Purl;
      expect(purl).toContain("epoch=0");
      expect(purl).toContain("upstream=libxml2@2.9.7");
    });
  });
});

describe("parseSourceRPM", () => {
  it("should correctly parse all valid source RPM strings from source_rpms.csv", () => {
    const csvFilePath = path.join(
      __dirname,
      "../../../../test/fixtures/rpm/source_rpms.csv",
    );
    let fileContent;
    try {
      fileContent = fs.readFileSync(csvFilePath, "utf-8");
    } catch (error) {
      throw new Error(
        `Failed to read source_rpms.csv: ${error.message}. Please ensure the file exists at test/fixtures/rpm/source_rpms.csv.`,
      );
    }

    const sourceRpmStrings = fileContent
      .split(",")
      .filter((s) => s.trim() !== "");

    if (sourceRpmStrings.length === 0) {
      console.warn(
        "source_rpms.csv is empty or contains no valid entries. Test will pass trivially.",
      );
      return;
    }

    let failedCount = 0;
    sourceRpmStrings.forEach((rpmString) => {
      const parsed = parseSourceRPM(rpmString.trim());

      try {
        expect(parsed).toBeDefined();
        if (parsed) {
          expect(parsed.name).toEqual(expect.any(String));
          expect(parsed.name.length).toBeGreaterThan(0);
          expect(parsed.version).toEqual(expect.any(String));
          expect(parsed.version.length).toBeGreaterThan(0);
          expect(parsed.release).toEqual(expect.any(String));
          expect(parsed.release.length).toBeGreaterThan(0);
        }
      } catch (e) {
        console.error(`Failed to parse or assert: '${rpmString}'`, e);
        failedCount++;
      }
    });

    if (failedCount > 0) {
      throw new Error(
        `${failedCount} out of ${sourceRpmStrings.length} RPM strings failed parsing or assertion.`,
      );
    }
    expect(failedCount).toBe(0);
  });

  // Add more specific test cases if needed
  it("should return undefined for invalid or malformed source RPM strings", () => {
    expect(parseSourceRPM("invalid-rpm-string")).toBeUndefined();
    expect(parseSourceRPM("nameonly.src.rpm")).toBeUndefined();
    expect(parseSourceRPM("name-versiononly.src.rpm")).toBeUndefined();
    expect(parseSourceRPM("name-1.2.3-.src.rpm")).toBeUndefined(); // empty release
    expect(parseSourceRPM("name--release.src.rpm")).toBeUndefined(); // empty version
    expect(parseSourceRPM("-version-release.src.rpm")).toBeUndefined(); // empty name
    expect(parseSourceRPM("not-an-rpm-at-all")).toBeUndefined();
    expect(parseSourceRPM("")).toBeUndefined();
    expect(parseSourceRPM(undefined)).toBeUndefined();
  });

  it("should correctly parse known valid source RPM strings", () => {
    const cases: Array<{ input: string; expected: SourcePackage | undefined }> =
      [
        {
          input: "bash-5.1.16-4.el9.src.rpm",
          expected: {
            name: "bash",
            version: "5.1.16",
            release: "4.el9",
          },
        },
        {
          input: "libreport-filesystem-2.17.11-1.fc38.src.rpm",
          expected: {
            name: "libreport-filesystem",
            version: "2.17.11",
            release: "1.fc38",
          },
        },
        {
          input: "kernel-6.5.0-0.rc1.20230722gitb1c0ddc7f7e1.42.fc39.src.rpm",
          expected: {
            name: "kernel",
            version: "6.5.0",
            release: "0.rc1.20230722gitb1c0ddc7f7e1.42.fc39",
          },
        },
        {
          input: "hyphen-name-package-1.2.3-1.src.rpm",
          expected: {
            name: "hyphen-name-package",
            version: "1.2.3",
            release: "1",
          },
        },
      ];

    for (const tc of cases) {
      expect(parseSourceRPM(tc.input)).toEqual(tc.expected);
    }
  });
});
