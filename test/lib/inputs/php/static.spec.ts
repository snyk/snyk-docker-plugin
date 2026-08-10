import { sep } from "path";
import { getPhpAppFileContentAction } from "../../../../lib/inputs/php/static";

describe("PHP application file path matching", () => {
  const { filePathMatches } = getPhpAppFileContentAction;

  it("should match composer.json and composer.lock", () => {
    expect(filePathMatches(`${sep}app${sep}composer.json`)).toBe(true);
    expect(filePathMatches(`${sep}app${sep}composer.lock`)).toBe(true);
  });

  it("should match whiteout entries for composer.json and composer.lock", () => {
    expect(filePathMatches(`${sep}app${sep}.wh.composer.json`)).toBe(true);
    expect(filePathMatches(`${sep}app${sep}.wh.composer.lock`)).toBe(true);
  });

  it("should match vendor/composer/installed.json with forward slashes", () => {
    expect(filePathMatches("/app/vendor/composer/installed.json")).toBe(true);
  });

  it("should match vendor/composer/installed.json with backslashes (Windows)", () => {
    expect(
      filePathMatches("\\app\\vendor\\composer\\installed.json"),
    ).toBe(true);
  });

  it("should match the whiteout form of vendor/composer/installed.json", () => {
    expect(
      filePathMatches("/app/vendor/composer/.wh.installed.json"),
    ).toBe(true);
    expect(
      filePathMatches("\\app\\vendor\\composer\\.wh.installed.json"),
    ).toBe(true);
  });

  it("should not match an installed.json outside vendor/composer", () => {
    expect(filePathMatches("/app/installed.json")).toBe(false);
    expect(filePathMatches("/app/vendor/other/installed.json")).toBe(false);
    expect(filePathMatches("/app/composer/installed.json")).toBe(false);
  });
});
