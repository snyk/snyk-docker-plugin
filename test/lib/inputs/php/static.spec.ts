import { getPhpAppFileContentAction } from "../../../../lib/inputs/php/static";

describe("PHP app file path matching", () => {
  const { actionName, filePathMatches } = getPhpAppFileContentAction;

  it("keeps actionName as php-app-files", () => {
    expect(actionName).toBe("php-app-files");
  });

  describe("composer manifest and lock matching", () => {
    it("matches composer.json and composer.lock", () => {
      expect(filePathMatches("/app/composer.json")).toBe(true);
      expect(filePathMatches("/app/composer.lock")).toBe(true);
    });

    it("does not match composer.json.dist", () => {
      expect(filePathMatches("/app/composer.json.dist")).toBe(false);
    });
  });

  describe("vendor/composer/installed.json matching", () => {
    it("matches installed.json under vendor/composer with forward slashes", () => {
      expect(filePathMatches("/app/vendor/composer/installed.json")).toBe(true);
      expect(filePathMatches("/srv/site/vendor/composer/installed.json")).toBe(
        true,
      );
    });

    it("matches installed.json under vendor/composer with backslashes (Windows)", () => {
      expect(filePathMatches("\\app\\vendor\\composer\\installed.json")).toBe(
        true,
      );
    });

    it("matches .wh. whiteout installed.json under vendor/composer", () => {
      expect(filePathMatches("/app/vendor/composer/.wh.installed.json")).toBe(
        true,
      );
    });

    it("does not match installed.json outside vendor/composer", () => {
      expect(filePathMatches("/app/vendor/foo/installed.json")).toBe(false);
      expect(filePathMatches("\\app\\vendor\\foo\\installed.json")).toBe(false);
      expect(filePathMatches("/opt/installed.json")).toBe(false);
    });
  });
});
