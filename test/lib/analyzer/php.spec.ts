import { readFileSync } from "fs";
import { join } from "path";
import { phpFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { DepGraphFact } from "../../../lib/facts";
import * as drupal10FilePathToContents from "../../fixtures/php/drupal10FilePathToContent.json";

function getDepGraphFact(
  facts: Array<{ type: string; data: unknown }>,
): DepGraphFact {
  return facts.find((fact) => fact.type === "depGraph") as DepGraphFact;
}

const fixturesRoot = join(__dirname, "../../fixtures/php");

describe("Can create dependency tree when some files are invalid", () => {
  it("Should succeed and return scan results", async () => {
    const scanResults = await phpFilesToScannedProjects(
      drupal10FilePathToContents,
    );
    expect(scanResults.length).toEqual(1);
  });
});

describe("Fallback dispatch for lock-only and installed.json-only projects", () => {
  it("builds a depGraph from a composer.lock with no sibling composer.json", async () => {
    const lockContent = readFileSync(
      join(fixturesRoot, "composer-lock-only.lock.json"),
      "utf8",
    );

    const scanResults = await phpFilesToScannedProjects({
      "/app/composer.lock": lockContent,
    });

    expect(scanResults).toHaveLength(1);
    const [result] = scanResults;
    expect(result.identity).toEqual({
      type: "composer",
      targetFile: "/app/composer.lock",
    });
    const pkgs = getDepGraphFact(result.facts).data.getDepPkgs();
    expect(pkgs).toEqual(
      expect.arrayContaining([
        { name: "vendor/pkg-a", version: "1.0.0" },
        { name: "vendor/pkg-b", version: "2.0.0" },
      ]),
    );
    expect(pkgs).not.toEqual(
      expect.arrayContaining([{ name: "vendor/dev-only", version: "0.1.0" }]),
    );
  });

  it("builds a depGraph from vendor/composer/installed.json when neither manifest nor lock is present", async () => {
    const installedContent = readFileSync(
      join(fixturesRoot, "vendor-composer-installed.json"),
      "utf8",
    );

    const scanResults = await phpFilesToScannedProjects({
      "/app/vendor/composer/installed.json": installedContent,
    });

    expect(scanResults).toHaveLength(1);
    const [result] = scanResults;
    expect(result.identity).toEqual({
      type: "composer",
      targetFile: "/app/vendor/composer/installed.json",
    });
    const pkgs = getDepGraphFact(result.facts).data.getDepPkgs();
    expect(pkgs).toEqual(
      expect.arrayContaining([
        { name: "symfony/console", version: "v6.4.0" },
        { name: "symfony/polyfill-mbstring", version: "v1.28.0" },
      ]),
    );
  });

  it("does not report a manifest-only project", async () => {
    const scanResults = await phpFilesToScannedProjects({
      "/app/composer.json": JSON.stringify({ name: "vendor/app" }),
    });

    expect(scanResults).toHaveLength(0);
  });

  it("prefers a composer.lock over installed.json in the same project root, never double-reporting", async () => {
    const installedContent = readFileSync(
      join(fixturesRoot, "vendor-composer-installed.json"),
      "utf8",
    );

    const scanResults = await phpFilesToScannedProjects({
      "/app/composer.lock": JSON.stringify({
        packages: [{ name: "vendor/pkg-a", version: "1.0.0" }],
        "packages-dev": [],
      }),
      "/app/vendor/composer/installed.json": installedContent,
    });

    expect(scanResults).toHaveLength(1);
    expect(scanResults[0].identity.targetFile).toEqual("/app/composer.lock");
  });
});
