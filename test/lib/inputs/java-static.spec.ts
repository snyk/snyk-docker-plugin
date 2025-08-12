import {
  getJarFileContentAction,
  getUsrLibJarFileContentAction,
} from "../../../lib/inputs/java/static";

describe("Java static input", () => {
  describe("getJarFileContentAction", () => {
    it("should exclude /usr/lib JARs by default", () => {
      expect(getJarFileContentAction.actionName).toBe("jar");
      expect(getJarFileContentAction.filePathMatches).toBeDefined();

      // Test that /usr/lib JARs are excluded
      const usrLibJar = "/usr/lib/java/some-lib.jar";
      expect(getJarFileContentAction.filePathMatches!(usrLibJar)).toBe(false);

      // Test that gradle cache is still excluded
      const gradleCacheJar = "/gradle/cache/some-lib.jar";
      expect(getJarFileContentAction.filePathMatches!(gradleCacheJar)).toBe(
        false,
      );

      // Test regular JARs are included
      const regularJar = "/app/lib/app.jar";
      expect(getJarFileContentAction.filePathMatches!(regularJar)).toBe(true);
    });

    it("should only match JAR and WAR files", () => {
      // Test JAR files
      expect(getJarFileContentAction.filePathMatches!("/app/lib/app.jar")).toBe(
        true,
      );

      // Test WAR files
      expect(getJarFileContentAction.filePathMatches!("/app/lib/app.war")).toBe(
        true,
      );

      // Test non-archive files
      expect(getJarFileContentAction.filePathMatches!("/app/lib/app.txt")).toBe(
        false,
      );
      expect(
        getJarFileContentAction.filePathMatches!("/app/lib/app.class"),
      ).toBe(false);
      expect(getJarFileContentAction.filePathMatches!("/app/lib/app.xml")).toBe(
        false,
      );
    });

    it("should exclude gradle cache paths", () => {
      const gradleCacheJar =
        "/home/user/.gradle/cache/modules-2/files-2.1/some-lib.jar";
      expect(getJarFileContentAction.filePathMatches!(gradleCacheJar)).toBe(
        false,
      );
    });
  });

  describe("getUsrLibJarFileContentAction", () => {
    it("should only include JARs from /usr/lib", () => {
      expect(getUsrLibJarFileContentAction.actionName).toBe("jar");
      expect(getUsrLibJarFileContentAction.filePathMatches).toBeDefined();

      // Test that /usr/lib JARs are included
      const usrLibJar = "/usr/lib/java/some-lib.jar";
      expect(getUsrLibJarFileContentAction.filePathMatches!(usrLibJar)).toBe(
        true,
      );

      // Test that non-/usr/lib JARs are excluded
      const regularJar = "/app/lib/app.jar";
      expect(getUsrLibJarFileContentAction.filePathMatches!(regularJar)).toBe(
        false,
      );

      // Test that gradle cache is excluded (even though it wouldn't contain /usr/lib)
      const gradleCacheJar = "/gradle/cache/some-lib.jar";
      expect(
        getUsrLibJarFileContentAction.filePathMatches!(gradleCacheJar),
      ).toBe(false);
    });

    it("should only match JAR and WAR files in /usr/lib", () => {
      // Test JAR files in /usr/lib
      expect(
        getUsrLibJarFileContentAction.filePathMatches!("/usr/lib/app.jar"),
      ).toBe(true);

      // Test WAR files in /usr/lib
      expect(
        getUsrLibJarFileContentAction.filePathMatches!("/usr/lib/app.war"),
      ).toBe(true);

      // Test non-archive files in /usr/lib
      expect(
        getUsrLibJarFileContentAction.filePathMatches!("/usr/lib/app.txt"),
      ).toBe(false);
      expect(
        getUsrLibJarFileContentAction.filePathMatches!("/usr/lib/app.class"),
      ).toBe(false);
      expect(
        getUsrLibJarFileContentAction.filePathMatches!("/usr/lib/app.xml"),
      ).toBe(false);
    });

    it("should match nested paths within /usr/lib", () => {
      const nestedUsrLibJar = "/usr/lib/java/jvm/lib/some-lib.jar";
      expect(
        getUsrLibJarFileContentAction.filePathMatches!(nestedUsrLibJar),
      ).toBe(true);
    });
  });
});
