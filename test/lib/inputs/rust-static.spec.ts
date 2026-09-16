import { getRustAppFileContentAction } from "../../../lib/inputs/rust/static";
import { streamToString } from "../../../lib/stream-utils";

describe("Rust app file path matching", () => {
  const { filePathMatches, actionName, callback } = getRustAppFileContentAction;

  it("should match application Cargo.lock files", () => {
    expect(filePathMatches("/app/Cargo.lock")).toBe(true);
    expect(filePathMatches("/usr/src/app/Cargo.lock")).toBe(true);
    expect(filePathMatches("/app/.wh.Cargo.lock")).toBe(true);
    expect(filePathMatches("C:\\app\\Cargo.lock")).toBe(true);
  });

  it("should not match non-Cargo.lock files or cache paths", () => {
    expect(filePathMatches("/app/Cargo.toml")).toBe(false);
    expect(filePathMatches("/app/package.json")).toBe(false);
    expect(
      filePathMatches(
        "/usr/local/cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.197/Cargo.lock",
      ),
    ).toBe(false);
    expect(
      filePathMatches("/root/.cargo/git/checkouts/foo-abc123/Cargo.lock"),
    ).toBe(false);
    expect(
      filePathMatches(
        "/usr/local/cargo/git/checkouts/my-dep-1a2b3c4d/9f8e7d6/Cargo.lock",
      ),
    ).toBe(false);
    expect(
      filePathMatches("/app/target/package/mycrate-0.1.0/Cargo.lock"),
    ).toBe(false);
    expect(
      filePathMatches("/app/vendor/some-crate-1.2.3/Cargo.lock"),
    ).toBe(false);
    expect(filePathMatches("")).toBe(false);
  });

  it("should expose the rust-app-files action with streamToString callback", () => {
    expect(actionName).toBe("rust-app-files");
    expect(callback).toBe(streamToString);
  });
});
