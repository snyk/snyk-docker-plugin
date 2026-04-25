import {
  computeImageSupport,
  SUPPORTED_DISTROS_URL,
  UNSUPPORTED_OS_NAMES,
} from "../../lib/image-support";

const TARGET = "example.com/image:latest";

describe("computeImageSupport", () => {
  describe("UNSUPPORTED_OS_NAMES constant", () => {
    it("should contain 'unknown' sentinel", () => {
      expect(UNSUPPORTED_OS_NAMES.has("unknown")).toBe(true);
    });
  });

  describe("supported images", () => {
    it("returns supported for a debian image with packages", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: {
          name: "debian",
          version: "11",
          prettyName: "Debian GNU/Linux 11 (bullseye)",
        },
        packageFormat: "deb",
        hasAnyPackages: true,
      });
      expect(result.status).toBe("supported");
      expect(result.reason).toBeUndefined();
    });

    it("returns supported for an alpine image with packages", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: {
          name: "alpine",
          version: "3.18.0",
          prettyName: "Alpine Linux v3.18",
        },
        packageFormat: "apk",
        hasAnyPackages: true,
      });
      expect(result.status).toBe("supported");
      expect(result.reason).toBeUndefined();
    });

    it("returns supported for a chisel image with packages", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "chisel", version: "0.0", prettyName: "" },
        packageFormat: "deb",
        hasAnyPackages: true,
      });
      expect(result.status).toBe("supported");
      expect(result.reason).toBeUndefined();
    });

    it("returns supported for a scratch image that has application dependencies", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "scratch", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
        hasApplicationDependencies: true,
      });
      expect(result.status).toBe("supported");
      expect(result.reason).toBeUndefined();
    });

    it("includes detectedOs and targetImage in supported result", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "ubuntu", version: "22.04", prettyName: "Ubuntu 22.04" },
        packageFormat: "deb",
        hasAnyPackages: true,
      });
      expect(result.status).toBe("supported");
      expect(result.detectedOs).toEqual({ name: "ubuntu", version: "22.04", prettyName: "Ubuntu 22.04" });
      expect(result.targetImage).toBe(TARGET);
    });
  });

  describe("unsupported: unknown-os", () => {
    it("returns unsupported/unknown-os when osRelease.name is 'unknown' and no packages", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "unknown", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("unknown-os");
    });

    it("returns unsupported/unknown-os even when packageFormat is non-linux for unknown OS", () => {
      // unknown-os takes precedence over other signals
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "unknown", version: "0.0", prettyName: "" },
        packageFormat: "deb",
        hasAnyPackages: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("unknown-os");
    });

    it("includes message with docs URL for unknown-os", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "unknown", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.message).toContain("unknown-os");
      expect(result.message).toContain(SUPPORTED_DISTROS_URL);
    });

    it("includes detectedOs for unknown-os", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "unknown", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.detectedOs).toEqual({ name: "unknown", version: "0.0", prettyName: "" });
      expect(result.targetImage).toBe(TARGET);
    });
  });

  describe("unsupported: scratch-image", () => {
    it("returns unsupported/scratch-image for scratch os with no app deps", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "scratch", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
        hasApplicationDependencies: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("scratch-image");
    });

    it("returns unsupported/scratch-image when hasApplicationDependencies is undefined (falsy)", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "scratch", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("scratch-image");
    });

    it("includes message with docs URL for scratch-image", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "scratch", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.message).toContain("scratch-image");
      expect(result.message).toContain(SUPPORTED_DISTROS_URL);
    });
  });

  describe("unsupported: no-package-manager", () => {
    it("returns unsupported/no-package-manager when OS detected but packageFormat is 'linux' with no packages", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "debian", version: "11", prettyName: "Debian GNU/Linux 11" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("no-package-manager");
    });

    it("returns unsupported/no-package-manager for alpine with linux package format and no packages", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "alpine", version: "3.18", prettyName: "Alpine Linux v3.18" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("no-package-manager");
    });

    it("returns supported when packageFormat is linux but hasAnyPackages is true", () => {
      // Edge case: packageFormat "linux" but with packages should not be flagged
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "debian", version: "11", prettyName: "Debian GNU/Linux 11" },
        packageFormat: "linux",
        hasAnyPackages: true,
      });
      expect(result.status).toBe("supported");
    });

    it("includes message with docs URL for no-package-manager", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "debian", version: "11", prettyName: "Debian GNU/Linux 11" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.message).toContain("no-package-manager");
      expect(result.message).toContain(SUPPORTED_DISTROS_URL);
    });
  });

  describe("unsupported: windows-image", () => {
    it("returns unsupported/windows-image for windows OS name", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "windows", version: "10.0", prettyName: "Windows Server 2022" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("windows-image");
    });

    it("returns unsupported/windows-image even with packages present (windows takes priority)", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "windows", version: "10.0", prettyName: "Windows Server 2022" },
        packageFormat: "deb",
        hasAnyPackages: true,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("windows-image");
    });

    it("is case-insensitive for 'windows' OS name", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "Windows", version: "10.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.status).toBe("unsupported");
      expect(result.reason).toBe("windows-image");
    });

    it("includes message with docs URL for windows-image", () => {
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "windows", version: "10.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.message).toContain("windows-image");
      expect(result.message).toContain(SUPPORTED_DISTROS_URL);
    });
  });

  describe("priority ordering", () => {
    it("windows-image takes precedence over unknown-os", () => {
      // hypothetical scenario where name is both windows-like and unknown
      const result = computeImageSupport({
        targetImage: TARGET,
        osRelease: { name: "windows", version: "0.0", prettyName: "" },
        packageFormat: "linux",
        hasAnyPackages: false,
      });
      expect(result.reason).toBe("windows-image");
    });
  });
});
