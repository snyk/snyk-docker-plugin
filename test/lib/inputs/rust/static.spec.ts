import { getRustAppFileContentAction } from "../../../../lib/inputs/rust/static";

describe("Rust app file path matching", () => {
  const { filePathMatches } = getRustAppFileContentAction;

  it("matches application Cargo.lock and Cargo.toml paths", () => {
    expect(filePathMatches("/app/Cargo.lock")).toBe(true);
    expect(filePathMatches("/app/Cargo.toml")).toBe(true);
  });

  it("matches .wh.-prefixed names for consistency with sibling inputs", () => {
    expect(filePathMatches("/app/.wh.Cargo.lock")).toBe(true);
    expect(filePathMatches("/app/.wh.Cargo.toml")).toBe(true);
  });

  it("rejects wrong-case, backup, and source file paths", () => {
    expect(filePathMatches("/app/cargo.lock")).toBe(false);
    expect(filePathMatches("/app/Cargo.lock.bak")).toBe(false);
    expect(filePathMatches("/app/src/main.rs")).toBe(false);
  });

  it("rejects registry, git checkout, and stdlib manifest paths", () => {
    expect(
      filePathMatches(
        "/usr/local/cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.0/Cargo.toml",
      ),
    ).toBe(false);
    expect(
      filePathMatches(
        "/root/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.0/Cargo.toml",
      ),
    ).toBe(false);
    expect(
      filePathMatches("/root/.cargo/git/checkouts/foo/abc123/Cargo.toml"),
    ).toBe(false);
    expect(
      filePathMatches(
        "/usr/local/rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/Cargo.toml",
      ),
    ).toBe(false);
  });
});
