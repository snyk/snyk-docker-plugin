import { getErrorMessage } from "../../lib/error-utils";
import { GoFileNameError } from "../../lib/go-parser/go-binary";

describe("getErrorMessage", () => {
  describe("when the caught value is an Error instance", () => {
    test("returns the .message of a plain Error", () => {
      expect(getErrorMessage(new Error("boom"))).toBe("boom");
    });

    test("returns the .message of a custom Error subclass", () => {
      const err = new GoFileNameError("main.go", "github.com/org/mod@v1.0.0");
      expect(getErrorMessage(err)).toBe(err.message);
    });

    test("returns an empty string when .message is empty", () => {
      expect(getErrorMessage(new Error(""))).toBe("");
    });
  });

  describe("when the caught value is not an Error instance", () => {
    test("returns a thrown string as-is", () => {
      expect(getErrorMessage("something broke")).toBe("something broke");
    });

    test("stringifies a plain object", () => {
      expect(getErrorMessage({ code: 42 })).toBe("[object Object]");
    });

    test("stringifies undefined", () => {
      expect(getErrorMessage(undefined)).toBe("undefined");
    });

    test("stringifies null", () => {
      expect(getErrorMessage(null)).toBe("null");
    });

    test("stringifies a number", () => {
      expect(getErrorMessage(404)).toBe("404");
    });

    test("stringifies a boolean", () => {
      expect(getErrorMessage(false)).toBe("false");
    });
  });
});
