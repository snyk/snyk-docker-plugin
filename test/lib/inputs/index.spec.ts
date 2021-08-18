import {
  getBufferContent,
  getElfFileContent,
  getFileContent,
} from "../../../lib/inputs";

describe("lib/inputs", () => {
  describe("getBufferContent", () => {
    it("should return 2 results if both are of type Buffer", () => {
      // Arrange
      const dummyExtractedLayers = {
        "foo/bar.jar": { jar: Buffer.from("hello world") },
        "bla/yada.jar": { jar: Buffer.from("hello again") },
      };

      // Act
      const result = getBufferContent(dummyExtractedLayers, "jar");

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          "foo/bar.jar": expect.any(Buffer),
          "bla/yada.jar": expect.any(Buffer),
        }),
      );
    });

    it("should throw if one of the types is not a buffer", () => {
      // Arrange
      const dummyExtractedLayers = {
        "foo/bar.jar": { jar: Buffer.from("hello world") },
        "bla/yada.jar": { jar: "not a buffer!" },
      };

      // Act and Assert
      expect(() => getBufferContent(dummyExtractedLayers, "jar")).toThrowError(
        "expected Buffer",
      );
    });
  });

  describe("getFileContent", () => {
    it("should return 2 results if both are of type string", () => {
      // Arrange
      const dummyExtractedLayers = {
        "foo/bar": { "node-app-files": "hello world" },
        "bla/yada": { "node-app-files": "hello again" },
      };

      // Act
      const result = getFileContent(dummyExtractedLayers, "node-app-files");

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          "foo/bar": expect.any(String),
          "bla/yada": expect.any(String),
        }),
      );
    });

    it("should throw if one of the types is not a string", () => {
      // Arrange
      const dummyExtractedLayers = {
        "foo/bar": { "node-app-files": "hello world" },
        "bla/yada": { "node-app-files": Buffer.from("not a string!") },
      };

      // Act and Assert
      expect(() =>
        getFileContent(dummyExtractedLayers, "node-app-files"),
      ).toThrowError("expected string");
    });
  });

  describe("getElfFileContent", () => {
    it("should return 2 results if both are of type Elf", () => {
      // Arrange

      const dummyExtractedLayers = {
        "foo/bar": { gomodules: { body: { programs: [], sections: [] } } },
        "bla/yada": { gomodules: { body: { programs: [], sections: [] } } },
      };

      // Act
      const result = getElfFileContent(dummyExtractedLayers, "gomodules");

      // Assert
      expect(result).toEqual(
        expect.objectContaining({
          "foo/bar": expect.any(Object),
          "bla/yada": expect.any(Object),
        }),
      );
    });

    it("should throw if one of the types is not an Elf", () => {
      // Arrange
      const dummyExtractedLayers = {
        "foo/bar": { gomodules: { body: { programs: [], sections: [] } } },
        "bla/yada": { gomodules: { body: { programs: ["no sections"] } } },
      };

      // Act and Assert
      expect(() =>
        getElfFileContent(dummyExtractedLayers as any, "gomodules"),
      ).toThrowError("elf file expected to contain programs and sections");
    });
  });
});
