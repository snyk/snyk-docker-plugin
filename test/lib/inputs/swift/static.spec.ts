import { getSwiftAppFileContentAction } from "../../../../lib/inputs/swift/static";

describe("Swift Package.resolved file path matching", () => {
  const { filePathMatches } = getSwiftAppFileContentAction;

  it("should match Package.resolved files", () => {
    expect(filePathMatches("/app/Package.resolved")).toBe(true);
  });

  it("should match whiteout Package.resolved files", () => {
    expect(filePathMatches("/app/.wh.Package.resolved")).toBe(true);
  });

  it("should not match non-lockfile Swift or other package manager files", () => {
    expect(filePathMatches("/app/Package.swift")).toBe(false);
    expect(filePathMatches("/app/package.json")).toBe(false);
    expect(filePathMatches("/app/Package.resolved.bak")).toBe(false);
  });

  it("should exclude vendored lockfiles under .build/checkouts/", () => {
    expect(
      filePathMatches("/app/.build/checkouts/swift-nio/Package.resolved"),
    ).toBe(false);
  });
});
