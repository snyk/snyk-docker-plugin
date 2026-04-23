import {
  getBaseImageLifecycleStatus,
  BaseImageLifecycleStatus,
  LifecycleStatus,
} from "../../lib/base-image-lifecycle";

describe("getBaseImageLifecycleStatus", () => {
  // Reference date well within 2026 so EOL expectations are deterministic
  const REFERENCE_DATE = "2026-04-23";

  describe("Ubuntu", () => {
    it("marks Ubuntu 18.04 as EOL", () => {
      const result = getBaseImageLifecycleStatus("ubuntu", "18.04", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2023-04-30");
    });

    it("marks Ubuntu 20.04 as EOL (EOL April 2025)", () => {
      const result = getBaseImageLifecycleStatus("ubuntu", "20.04", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2025-04-30");
    });

    it("marks Ubuntu 22.04 as maintained", () => {
      const result = getBaseImageLifecycleStatus("ubuntu", "22.04", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("maintained");
      expect(result.endOfLifeDate).toBe("2027-04-30");
    });

    it("marks Ubuntu 24.04 as maintained", () => {
      const result = getBaseImageLifecycleStatus("ubuntu", "24.04", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("maintained");
      expect(result.endOfLifeDate).toBe("2029-04-30");
    });

    it("handles mixed-case distro name (Ubuntu vs ubuntu)", () => {
      const result = getBaseImageLifecycleStatus("Ubuntu", "22.04", REFERENCE_DATE);
      expect(result.lifecycleStatus).toBe("maintained");
    });
  });

  describe("Debian", () => {
    it("marks Debian 9 as EOL", () => {
      const result = getBaseImageLifecycleStatus("debian", "9", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2022-06-30");
    });

    it("marks Debian 10 as EOL (EOL June 2024)", () => {
      const result = getBaseImageLifecycleStatus("debian", "10", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2024-06-30");
    });

    it("marks Debian 11 as maintained", () => {
      const result = getBaseImageLifecycleStatus("debian", "11", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("maintained");
      expect(result.endOfLifeDate).toBe("2026-08-15");
    });

    it("marks Debian 12 as maintained", () => {
      const result = getBaseImageLifecycleStatus("debian", "12", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("maintained");
    });
  });

  describe("Alpine", () => {
    it("marks Alpine 3.15 as EOL", () => {
      const result = getBaseImageLifecycleStatus("alpine", "3.15.4", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2023-11-01");
    });

    it("marks Alpine 3.18 as EOL (EOL May 2025)", () => {
      const result = getBaseImageLifecycleStatus("alpine", "3.18.0", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2025-05-09");
    });

    it("marks Alpine 3.20 as EOL (EOL April 2026)", () => {
      const result = getBaseImageLifecycleStatus("alpine", "3.20.0", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2026-04-01");
    });

    it("marks Alpine 3.21 as maintained", () => {
      const result = getBaseImageLifecycleStatus("alpine", "3.21.0", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("maintained");
      expect(result.endOfLifeDate).toBe("2026-11-01");
    });

    it("strips patch component when looking up Alpine version", () => {
      // Same minor version, different patch → same result
      const result1 = getBaseImageLifecycleStatus("alpine", "3.21.0", REFERENCE_DATE);
      const result2 = getBaseImageLifecycleStatus("alpine", "3.21.5", REFERENCE_DATE);
      expect(result1.lifecycleStatus).toBe(result2.lifecycleStatus);
    });
  });

  describe("Amazon Linux", () => {
    it("marks Amazon Linux 1 as EOL", () => {
      const result = getBaseImageLifecycleStatus("amzn", "1", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
    });

    it("marks Amazon Linux 2 as EOL (EOL June 2025)", () => {
      const result = getBaseImageLifecycleStatus("amzn", "2", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2025-06-30");
    });

    it("marks Amazon Linux 2023 as maintained", () => {
      const result = getBaseImageLifecycleStatus("amzn", "2023", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("maintained");
    });
  });

  describe("RHEL", () => {
    it("marks RHEL 7 as EOL (EOL June 2024)", () => {
      const result = getBaseImageLifecycleStatus("rhel", "7", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2024-06-30");
    });

    it("marks RHEL 8 as maintained", () => {
      const result = getBaseImageLifecycleStatus("rhel", "8", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("maintained");
    });

    it("strips minor version component for RHEL (e.g. 7.9 → 7)", () => {
      const result = getBaseImageLifecycleStatus("rhel", "7.9", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
    });
  });

  describe("CentOS", () => {
    it("marks CentOS 7 as EOL", () => {
      const result = getBaseImageLifecycleStatus("centos", "7", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
    });

    it("marks CentOS 8 as EOL (EOL December 2021)", () => {
      const result = getBaseImageLifecycleStatus("centos", "8", REFERENCE_DATE);
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
      expect(result.endOfLifeDate).toBe("2021-12-31");
    });
  });

  describe("Unknown distros", () => {
    it("returns unknown status for unrecognised distro", () => {
      const result = getBaseImageLifecycleStatus("foobarlinux", "1.0", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("unknown");
      expect(result.endOfLifeDate).toBeUndefined();
    });

    it("returns unknown status for recognised distro but unrecognised version", () => {
      const result = getBaseImageLifecycleStatus("ubuntu", "99.04", REFERENCE_DATE);
      expect(result.isEol).toBe(false);
      expect(result.lifecycleStatus).toBe("unknown");
      expect(result.endOfLifeDate).toBeUndefined();
    });

    it("returns unknown status for scratch images", () => {
      const result = getBaseImageLifecycleStatus("scratch", "0.0", REFERENCE_DATE);
      expect(result.lifecycleStatus).toBe("unknown");
    });

    it("returns unknown status for unknown OS", () => {
      const result = getBaseImageLifecycleStatus("unknown", "0.0", REFERENCE_DATE);
      expect(result.lifecycleStatus).toBe("unknown");
    });
  });

  describe("lifecycleStatus type correctness", () => {
    it("endOfLifeDate is absent when status is unknown", () => {
      const result = getBaseImageLifecycleStatus("nonexistent", "1.0", REFERENCE_DATE);
      expect(result.endOfLifeDate).toBeUndefined();
    });

    it("endOfLifeDate is present when status is eol", () => {
      const result = getBaseImageLifecycleStatus("ubuntu", "18.04", REFERENCE_DATE);
      expect(result.endOfLifeDate).toBeDefined();
      expect(typeof result.endOfLifeDate).toBe("string");
    });

    it("endOfLifeDate is present when status is maintained", () => {
      const result = getBaseImageLifecycleStatus("ubuntu", "22.04", REFERENCE_DATE);
      expect(result.endOfLifeDate).toBeDefined();
    });

    it("uses current date when referenceDate is not provided", () => {
      // Ubuntu 18.04 has been EOL since April 2023 – should always be EOL from now on
      const result = getBaseImageLifecycleStatus("ubuntu", "18.04");
      expect(result.isEol).toBe(true);
      expect(result.lifecycleStatus).toBe("eol");
    });
  });
});
