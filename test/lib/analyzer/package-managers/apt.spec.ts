import { purl } from "../../../../lib/analyzer/package-sources/package-managers/apt";
import type { AnalyzedPackageWithVersion } from "../../../../lib/analyzer/types";

describe("purl()", () => {
  it.each([
    [{ Name: undefined, Version: undefined }],
    [{ Name: "foo", Version: undefined }],
    [{ Name: undefined, Version: "bar" }],
  ])("does not build a purl if Name or Version is missing: %s", (pkg) => {
    expect(purl(pkg as unknown as AnalyzedPackageWithVersion)).toBeUndefined();
  });

  it("constructs a purl with name and version", () => {
    expect(
      purl({
        Name: "bar",
        Version: "1.2.3-4",
      } as unknown as AnalyzedPackageWithVersion),
    ).toEqual("pkg:deb/bar@1.2.3-4");
  });

  it("constructs a purl with source name", () => {
    expect(
      purl({
        Source: "foo",
        Name: "bar",
        Version: "1.2.3-4",
      } as unknown as AnalyzedPackageWithVersion),
    ).toEqual("pkg:deb/bar@1.2.3-4?upstream=foo");
  });

  it("constructs a purl with upstream name and version", () => {
    expect(
      purl({
        Source: "foo",
        SourceVersion: "5.6.7+8",
        Name: "bar",
        Version: "1.2.3-4",
      } as unknown as AnalyzedPackageWithVersion),
    ).toEqual("pkg:deb/bar@1.2.3-4?upstream=foo%405.6.7%2B8");
  });
});
