import {
  CARGO_IGNORED_PATH_PATTERNS,
  getCargoAppFileContentAction,
} from "../../../../lib/inputs/cargo/static";
import { streamToString } from "../../../../lib/stream-utils";

describe("Cargo application file path matching", () => {
  const { filePathMatches, actionName, callback } =
    getCargoAppFileContentAction;

  it("exports getCargoAppFileContentAction with expected actionName and callback", () => {
    expect(actionName).toBe("cargo-app-files");
    expect(callback).toBe(streamToString);
  });

  describe("application manifest paths (forward slashes)", () => {
    it.each([
      "/app/Cargo.lock",
      "/srv/a/b/c/Cargo.lock",
      "/app/Cargo.toml",
      "/srv/a/b/c/Cargo.toml",
      "/app/vendor-lib/Cargo.toml",
    ])("matches %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(true);
    });
  });

  describe("application manifest paths (backslashes)", () => {
    it.each(["\\app\\Cargo.lock", "\\app\\Cargo.toml"])(
      "matches %s",
      (filePath) => {
        expect(filePathMatches(filePath)).toBe(true);
      },
    );
  });

  describe("ignored cache and vendor paths (forward slashes)", () => {
    it.each([
      "/app/vendor/serde/Cargo.toml",
      "/root/.cargo/registry/src/index.crates.io-abc/serde-1.0.0/Cargo.toml",
      "/root/.cargo/git/checkouts/foo/Cargo.lock",
    ])("does not match %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(false);
    });

    it.each(CARGO_IGNORED_PATH_PATTERNS)(
      "does not match a path containing ignored pattern %s",
      (pattern) => {
        const filePath = `/ignored-root/${pattern}example/Cargo.lock`;
        expect(filePath).toContain(pattern);
        expect(filePathMatches(filePath)).toBe(false);
      },
    );
  });

  describe("ignored cache and vendor paths (backslashes)", () => {
    it.each([
      "\\root\\.cargo\\registry\\src\\serde-1.0.0\\Cargo.toml",
      "\\app\\vendor\\serde\\Cargo.toml",
    ])("does not match %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(false);
    });
  });

  describe("whiteout paths", () => {
    it.each(["/app/.wh.Cargo.lock", "/app/.wh.Cargo.toml", "/app/.wh..wh.opq"])(
      "does not match %s",
      (filePath) => {
        expect(filePathMatches(filePath)).toBe(false);
      },
    );
  });

  describe("similarly-named non-matching files", () => {
    it.each([
      "/app/Cargo.lock.bak",
      "/app/notCargo.lock",
      "/app/Cargo.toml.orig",
      "/app/cargo.lock",
    ])("does not match %s", (filePath) => {
      expect(filePathMatches(filePath)).toBe(false);
    });
  });
});
