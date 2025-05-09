import * as fs from "fs";
import * as path from "path";
import { parseSourceRPM } from "../../../../lib/analyzer/package-managers/rpm";
import { SourcePackage } from "../../../../lib/analyzer/types";

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
