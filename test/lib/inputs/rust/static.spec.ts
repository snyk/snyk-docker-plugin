import { getCargoAppFileContentAction } from "../../../../lib/inputs/rust/static";

describe("Cargo app file path matching", () => {
  const { filePathMatches, actionName, callback } =
    getCargoAppFileContentAction;

  it("uses the cargo-app-files action name and streamToString callback", () => {
    expect(actionName).toBe("cargo-app-files");
    expect(typeof callback).toBe("function");
  });

  it("matches Cargo.lock and Cargo.toml at application paths", () => {
    expect(filePathMatches("/app/Cargo.lock")).toBe(true);
    expect(filePathMatches("/app/Cargo.toml")).toBe(true);
  });

  it("matches .wh. whiteout variants", () => {
    expect(filePathMatches("/app/.wh.Cargo.lock")).toBe(true);
    expect(filePathMatches("/app/.wh.Cargo.toml")).toBe(true);
  });

  it("does not match case variants or backup suffixes", () => {
    expect(filePathMatches("/app/cargo.lock")).toBe(false);
    expect(filePathMatches("/app/Cargo.lock.bak")).toBe(false);
  });

  it("does not match Rust source files", () => {
    expect(filePathMatches("/app/src/main.rs")).toBe(false);
  });

  it("does not match vendored registry Cargo.toml copies", () => {
    expect(
      filePathMatches(
        "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.0/Cargo.toml",
      ),
    ).toBe(false);
  });

  it("does not match rustup toolchain source Cargo.toml copies", () => {
    expect(
      filePathMatches(
        "/usr/local/rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/Cargo.toml",
      ),
    ).toBe(false);
  });
});
