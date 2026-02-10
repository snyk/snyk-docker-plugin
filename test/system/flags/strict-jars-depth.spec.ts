import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("use-strict-jars-depth flag", () => {
  const fixturePath = getFixture(
    "docker-archives/docker-save/java-uberjar.tar",
  );
  const imageNameAndTag = `docker-archive:${fixturePath}`;

  describe("lenient mode (default)", () => {
    it("accepts boolean true for nested-jars-depth when use-strict-jars-depth is undefined", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "nested-jars-depth": true,
      });

      expect(result.scanResults).toBeDefined();
    });

    it("accepts both shaded-jars-depth and nested-jars-depth when use-strict-jars-depth is undefined", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "shaded-jars-depth": "2",
        "nested-jars-depth": "1",
      });

      expect(result.scanResults).toBeDefined();
    });

    it("accepts boolean true when use-strict-jars-depth is false", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "nested-jars-depth": true,
        "use-strict-jars-depth": false,
      });

      expect(result.scanResults).toBeDefined();
    });

    it("accepts both flags when use-strict-jars-depth is false", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "shaded-jars-depth": "2",
        "nested-jars-depth": "1",
        "use-strict-jars-depth": false,
      });

      expect(result.scanResults).toBeDefined();
    });
  });

  describe("lenient mode with string values", () => {
    it("accepts boolean true when use-strict-jars-depth is 'false'", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "nested-jars-depth": true,
        "use-strict-jars-depth": "false",
      });

      expect(result.scanResults).toBeDefined();
    });

    it("accepts both flags when use-strict-jars-depth is 'false'", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "shaded-jars-depth": "2",
        "nested-jars-depth": "1",
        "use-strict-jars-depth": "false",
      });

      expect(result.scanResults).toBeDefined();
    });
  });

  describe("strict mode", () => {
    it("rejects boolean true for nested-jars-depth when use-strict-jars-depth is true", async () => {
      await expect(
        scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "nested-jars-depth": true,
          "use-strict-jars-depth": true,
        }),
      ).rejects.toThrow();
    });

    it("rejects boolean true for shaded-jars-depth when use-strict-jars-depth is true", async () => {
      await expect(
        scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "shaded-jars-depth": true,
          "use-strict-jars-depth": true,
        }),
      ).rejects.toThrow();
    });

    it("rejects both shaded-jars-depth and nested-jars-depth when use-strict-jars-depth is true", async () => {
      await expect(
        scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "shaded-jars-depth": "2",
          "nested-jars-depth": "1",
          "use-strict-jars-depth": true,
        }),
      ).rejects.toThrow();
    });

    it("rejects boolean true when use-strict-jars-depth is 'true'", async () => {
      await expect(
        scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "nested-jars-depth": true,
          "use-strict-jars-depth": "true",
        }),
      ).rejects.toThrow();
    });

    it("rejects whitespace-only string for nested-jars-depth when use-strict-jars-depth is true", async () => {
      await expect(
        scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "nested-jars-depth": " ",
          "use-strict-jars-depth": true,
        }),
      ).rejects.toThrow();
    });

    it("rejects whitespace-only string for shaded-jars-depth when use-strict-jars-depth is true", async () => {
      await expect(
        scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "shaded-jars-depth": " ",
          "use-strict-jars-depth": true,
        }),
      ).rejects.toThrow();
    });

    it("rejects both flags when use-strict-jars-depth is 'true'", async () => {
      await expect(
        scan({
          path: imageNameAndTag,
          "app-vulns": true,
          "shaded-jars-depth": "2",
          "nested-jars-depth": "1",
          "use-strict-jars-depth": "true",
        }),
      ).rejects.toThrow();
    });
  });

  describe("valid inputs work in both modes", () => {
    it("accepts numeric string in lenient mode", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "nested-jars-depth": "1",
      });

      expect(result.scanResults).toBeDefined();
    });

    it("accepts numeric string in strict mode", async () => {
      const result = await scan({
        path: imageNameAndTag,
        "app-vulns": true,
        "nested-jars-depth": "1",
        "use-strict-jars-depth": true,
      });

      expect(result.scanResults).toBeDefined();
    });
  });
});
