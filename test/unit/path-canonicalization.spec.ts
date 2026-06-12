import {
  canonicalizePath,
  normalizeAbsolutePath,
} from "../../lib/analyzer/package-managers/path-canonicalization";

describe("path-canonicalization", () => {
  it("normalizes paths to POSIX absolute form", () => {
    expect(normalizeAbsolutePath("usr/bin/node")).toBe("/usr/bin/node");
    expect(normalizeAbsolutePath("/bin/node")).toBe("/bin/node");
  });

  it("resolves symlinks when canonicalizing evidence paths", () => {
    const symlinkGraph = new Map<string, string>([
      ["/bin", "usr/bin"],
      ["/lib", "usr/lib"],
    ]);

    expect(canonicalizePath("/bin/node", symlinkGraph)).toBe("/usr/bin/node");
    expect(canonicalizePath("/lib/libc.so", symlinkGraph)).toBe(
      "/usr/lib/libc.so",
    );
  });

  it("returns the original path when no symlink exists", () => {
    const symlinkGraph = new Map<string, string>();
    expect(canonicalizePath("/opt/app/binary", symlinkGraph)).toBe(
      "/opt/app/binary",
    );
  });
});
