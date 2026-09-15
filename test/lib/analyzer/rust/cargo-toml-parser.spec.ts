import * as fs from "fs";
import * as path from "path";
import { parseCargoTomlRootPackage } from "../../../../lib/analyzer/applications/rust/cargo-toml-parser";

const fixturesPath = path.join(__dirname, "../../../fixtures/rust");

function loadFixture(relativePath: string): string {
  return fs.readFileSync(path.join(fixturesPath, relativePath), "utf-8");
}

describe("parseCargoTomlRootPackage", () => {
  it("returns name and version from [package]", () => {
    const content = loadFixture("simple/Cargo.toml");
    expect(parseCargoTomlRootPackage(content)).toEqual({
      name: "my-app",
      version: "0.1.0",
    });
  });

  it("returns name with version 0.0.0 for version.workspace = true", () => {
    const content = `[package]
name = "ws-member"
version.workspace = true`;
    expect(parseCargoTomlRootPackage(content)).toEqual({
      name: "ws-member",
      version: "0.0.0",
    });
  });

  it("returns name with version 0.0.0 for version = { workspace = true }", () => {
    const content = `[package]
name = "ws-member"
version = { workspace = true }`;
    expect(parseCargoTomlRootPackage(content)).toEqual({
      name: "ws-member",
      version: "0.0.0",
    });
  });

  it("returns undefined for workspace-only manifest", () => {
    const content = loadFixture("workspace/Cargo.toml");
    expect(parseCargoTomlRootPackage(content)).toBeUndefined();
  });

  it("does not pick up name from non-package tables", () => {
    const content = `[workspace.package]
name = "wrong"

[dependencies]
name = "also-wrong"`;
    expect(parseCargoTomlRootPackage(content)).toBeUndefined();
  });

  it("returns undefined for unparseable input", () => {
    expect(parseCargoTomlRootPackage("")).toBeUndefined();
    expect(parseCargoTomlRootPackage("{{not toml")).toBeUndefined();
  });
});
