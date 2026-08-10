import { readFileSync } from "fs";
import { join } from "path";
import {
  parseComposerLock,
  parseInstalledJson,
} from "../../lib/php-parser/composer-lock-parser";

const fixturesRoot = join(__dirname, "../fixtures/php");

function readFixture(relativePath: string): string {
  return readFileSync(join(fixturesRoot, relativePath), "utf8");
}

describe("composer lock parser", () => {
  it("parseComposerLock returns every packages entry as name and version in lockfile order", () => {
    const lockContent = readFixture("composer-lock-only.lock.json");

    const packages = parseComposerLock(lockContent);

    expect(packages).toEqual([
      { name: "vendor/pkg-a", version: "1.0.0" },
      { name: "vendor/pkg-b", version: "2.0.0" },
    ]);
  });

  it("parseComposerLock excludes packages-dev by default", () => {
    const lockContent = readFixture("composer-lock-only.lock.json");

    const packages = parseComposerLock(lockContent);

    expect(packages).not.toEqual(
      expect.arrayContaining([{ name: "vendor/dev-only", version: "0.1.0" }]),
    );
  });

  it("parseComposerLock includes packages-dev when shouldIncludeDevDependencies is true", () => {
    const lockContent = readFixture("composer-lock-only.lock.json");

    const packages = parseComposerLock(lockContent, {
      shouldIncludeDevDependencies: true,
    });

    expect(packages).toEqual([
      { name: "vendor/pkg-a", version: "1.0.0" },
      { name: "vendor/pkg-b", version: "2.0.0" },
      { name: "vendor/dev-only", version: "0.1.0" },
    ]);
  });

  it("parseInstalledJson handles Composer 2.x shape with a top-level packages key", () => {
    const installedContent = readFixture("vendor-composer-installed.json");

    const packages = parseInstalledJson(installedContent);

    expect(packages).toEqual([
      { name: "symfony/console", version: "v6.4.0" },
      { name: "symfony/polyfill-mbstring", version: "v1.28.0" },
    ]);
  });

  it("parseInstalledJson handles Composer 1.x shape as a top-level array", () => {
    const installedContent = JSON.stringify([
      { name: "monolog/monolog", version: "2.9.1" },
      { name: "psr/log", version: "3.0.0" },
    ]);

    const packages = parseInstalledJson(installedContent);

    expect(packages).toEqual([
      { name: "monolog/monolog", version: "2.9.1" },
      { name: "psr/log", version: "3.0.0" },
    ]);
  });

  it("returns an empty package list for malformed or non-JSON input instead of throwing", () => {
    expect(() => parseComposerLock("not json")).not.toThrow();
    expect(parseComposerLock("not json")).toEqual([]);

    expect(() => parseComposerLock("{")).not.toThrow();
    expect(parseComposerLock("{")).toEqual([]);

    expect(() => parseInstalledJson("")).not.toThrow();
    expect(parseInstalledJson("")).toEqual([]);

    expect(() => parseInstalledJson("null")).not.toThrow();
    expect(parseInstalledJson("null")).toEqual([]);
  });

  it("skips entries missing name or version instead of emitting undefined values", () => {
    const lockContent = readFixture("composer-lock-only.lock.json");

    const packages = parseComposerLock(lockContent);

    expect(packages.every((pkg) => pkg.name && pkg.version)).toBe(true);
    expect(packages).toHaveLength(2);
  });
});
