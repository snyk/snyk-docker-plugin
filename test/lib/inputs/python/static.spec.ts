import { sep } from "path";
import {
  getPipAppFileContentAction,
  getPythonAppFileContentAction,
} from "../../../../lib/inputs/python/static";

describe("Python pip file path matching", () => {
  const { filePathMatches } = getPipAppFileContentAction;

  describe("requirements.txt matching", () => {
    it("should match requirements.txt", () => {
      expect(filePathMatches("/app/requirements.txt")).toBe(true);
    });
  });

  describe("METADATA file matching", () => {
    it("should match METADATA files with forward slashes", () => {
      expect(
        filePathMatches(
          "/usr/lib/python3.9/dist-packages/Django-4.1.2.dist-info/METADATA",
        ),
      ).toBe(true);
      expect(
        filePathMatches(
          "/usr/lib/python3.9/site-packages/requests-2.28.0.dist-info/METADATA",
        ),
      ).toBe(true);
    });

    it("should match METADATA files with backslashes (Windows)", () => {
      expect(
        filePathMatches(
          "\\usr\\lib\\python3.9\\dist-packages\\Django-4.1.2.dist-info\\METADATA",
        ),
      ).toBe(true);
      expect(
        filePathMatches(
          "\\usr\\lib\\python3.9\\site-packages\\requests-2.28.0.dist-info\\METADATA",
        ),
      ).toBe(true);
    });

    it("should not match non-METADATA files in dist-info", () => {
      expect(
        filePathMatches(
          "/usr/lib/python3.9/dist-packages/Django-4.1.2.dist-info/RECORD",
        ),
      ).toBe(false);
    });

    it("should not match METADATA files outside of site/dist-packages", () => {
      expect(filePathMatches("/app/METADATA")).toBe(false);
      expect(filePathMatches("/usr/lib/METADATA")).toBe(false);
    });
  });
});

describe("Python application file path matching", () => {
  const { filePathMatches } = getPythonAppFileContentAction;

  it("should match .py, Pipfile and requirements.txt files", () => {
    expect(filePathMatches(`${sep}app${sep}main.py`)).toBe(true);
    expect(filePathMatches(`${sep}app${sep}Pipfile`)).toBe(true);
    expect(filePathMatches(`${sep}app${sep}requirements.txt`)).toBe(true);
  });

  it("should exclude files in site-packages and dist-packages", () => {
    expect(filePathMatches(`${sep}lib${sep}site-packages${sep}foo.py`)).toBe(
      false,
    );
    expect(filePathMatches(`${sep}lib${sep}dist-packages${sep}bar.py`)).toBe(
      false,
    );
  });

  it("should exclude files under /usr/", () => {
    expect(filePathMatches(`${sep}usr${sep}lib${sep}script.py`)).toBe(false);
  });
});
