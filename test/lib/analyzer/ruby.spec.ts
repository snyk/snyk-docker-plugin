import * as fs from "fs";
import * as path from "path";
import { rubyFilesToScannedProjects } from "../../../lib/analyzer/applications";
import { isInstalledGemLockfile } from "../../../lib/analyzer/applications/ruby";
import { getRubyAppFileContentAction } from "../../../lib/inputs/ruby/static";

const fixturesPath = path.join(__dirname, "../../fixtures/ruby");

function loadFixture(filename: string): string {
  return fs.readFileSync(path.join(fixturesPath, filename), "utf-8");
}

describe("ruby Gemfile.lock analyzer", () => {
  describe("basic Gemfile.lock parsing", () => {
    it("should parse a valid Gemfile.lock and produce a rubygems scan result", async () => {
      const content = loadFixture("simple.Gemfile.lock");
      const results = await rubyFilesToScannedProjects({
        "/app/Gemfile.lock": content,
      });

      expect(results).toHaveLength(1);
      expect(results[0].identity.type).toBe("rubygems");
      expect(results[0].identity.targetFile).toBe("/app/Gemfile.lock");

      const depGraphFact = results[0].facts.find((f) => f.type === "depGraph");
      expect(depGraphFact).toBeDefined();
      expect(depGraphFact!.data.pkgManager.name).toBe("rubygems");

      const pkgs = depGraphFact!.data.getPkgs();
      expect(
        pkgs.find((p) => p.name === "rack" && p.version === "1.6.4"),
      ).toBeDefined();
      expect(
        pkgs.find((p) => p.name === "rack-test" && p.version === "0.6.3"),
      ).toBeDefined();
    });

    it("should include testedFiles with Gemfile.lock and optional Gemfile", async () => {
      const content = loadFixture("simple.Gemfile.lock");
      const results = await rubyFilesToScannedProjects({
        "/app/Gemfile": "source 'https://rubygems.org'\ngem 'rack-test'\n",
        "/app/Gemfile.lock": content,
      });

      const testedFilesFact = results[0].facts.find(
        (f) => f.type === "testedFiles",
      );
      expect(testedFilesFact).toBeDefined();
      expect(testedFilesFact!.data).toEqual(["Gemfile", "Gemfile.lock"]);
    });

    it("should work with Gemfile.lock alone (Gemfile optional)", async () => {
      const content = loadFixture("simple.Gemfile.lock");
      const results = await rubyFilesToScannedProjects({
        "/app/Gemfile.lock": content,
      });

      expect(results).toHaveLength(1);
      const testedFilesFact = results[0].facts.find(
        (f) => f.type === "testedFiles",
      );
      expect(testedFilesFact!.data).toEqual(["Gemfile.lock"]);
    });
  });

  describe("malformed lockfiles", () => {
    it("should skip a malformed Gemfile.lock and still succeed", async () => {
      const results = await rubyFilesToScannedProjects({
        "/app/Gemfile.lock": "this is not a valid lockfile",
        "/other/Gemfile.lock": loadFixture("simple.Gemfile.lock"),
      });

      expect(results).toHaveLength(1);
      expect(results[0].identity.targetFile).toBe("/other/Gemfile.lock");
    });
  });

  describe("multiple lockfiles", () => {
    it("should produce two results for Gemfile.lock files in different directories", async () => {
      const content = loadFixture("simple.Gemfile.lock");
      const results = await rubyFilesToScannedProjects({
        "/app/one/Gemfile.lock": content,
        "/app/two/Gemfile.lock": content,
      });

      expect(results).toHaveLength(2);
      const targets = results.map((r) => r.identity.targetFile).sort();
      expect(targets).toEqual([
        "/app/one/Gemfile.lock",
        "/app/two/Gemfile.lock",
      ]);
    });
  });

  describe("deleted / missing lockfiles", () => {
    it("should not report a Gemfile.lock that is absent after whiteout merge", async () => {
      // Extractor drops whited-out paths before the analyzer runs; an absent
      // lockfile must not produce a result.
      const results = await rubyFilesToScannedProjects({
        "/app/Gemfile": "source 'https://rubygems.org'\n",
      });
      expect(results).toHaveLength(0);
    });

    it("should match Gemfile.lock whiteout paths for extraction", () => {
      expect(
        getRubyAppFileContentAction.filePathMatches!("/app/.wh.Gemfile.lock"),
      ).toBe(true);
      expect(
        getRubyAppFileContentAction.filePathMatches!("/app/.wh.Gemfile"),
      ).toBe(true);
      expect(
        getRubyAppFileContentAction.filePathMatches!("/app/Gemfile.lock"),
      ).toBe(true);
      expect(
        getRubyAppFileContentAction.filePathMatches!("/app/other.txt"),
      ).toBe(false);
    });
  });

  describe("installed gem lockfiles", () => {
    const skippedLockfiles = [
      "/usr/local/lib/ruby/gems/3.3.0/gems/rbs-3.4.0/Gemfile.lock",
      "/usr/local/lib/ruby/gems/3.3.0/gems/typeprof-0.21.9/Gemfile.lock",
      "/usr/local/bundle/gems/rack-test-0.6.3/Gemfile.lock",
      "/usr/local/bundle/bundler/gems/rails-abcdef1234567890abcdef12/Gemfile.lock",
      "/usr/local/bundle/bundler/gems/rails-0123456789abcdef01234567/Gemfile.lock",
    ];

    const reportedLockfiles = [
      "/app/Gemfile.lock",
      "/usr/local/bundle/Gemfile.lock",
      "/srv/gems/myapp-2/Gemfile.lock",
    ];

    it("should skip gem-home, bundle/gems, and bundler/gems lockfiles", () => {
      for (const lockPath of skippedLockfiles) {
        expect(isInstalledGemLockfile(lockPath)).toBe(true);
      }
    });

    it("should not skip application lockfiles outside install layouts", () => {
      for (const lockPath of reportedLockfiles) {
        expect(isInstalledGemLockfile(lockPath)).toBe(false);
      }
    });

    it("should skip install-layout lockfiles and still report app lockfiles", async () => {
      const content = loadFixture("simple.Gemfile.lock");
      const filePathToContent: { [path: string]: string } = {};
      for (const lockPath of [...skippedLockfiles, ...reportedLockfiles]) {
        filePathToContent[lockPath] = content;
      }

      const results = await rubyFilesToScannedProjects(filePathToContent);
      const targets = results.map((r) => r.identity.targetFile).sort();
      expect(targets).toEqual([...reportedLockfiles].sort());
    });
  });
});
