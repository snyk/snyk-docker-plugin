// tslint:disable:max-line-length
// tslint:disable:no-string-throw

import * as fs from "fs";
import * as path from "path";
import { ExtractedLayers } from "../../../lib/extractor/types";

import { detect } from "../../../lib/analyzer/os-release/static";

const getOsFixtureFiles = async (
  dir,
  extractAction,
): Promise<ExtractedLayers> => {
  const root = path.join(__dirname, "../../fixtures/os", dir, "fs");
  const fac: ExtractedLayers = {};

  async function* getFiles(dir) {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const res = path.resolve(dir, entry.name);
      if (entry.isDirectory()) {
        yield* getFiles(res);
      } else {
        yield res;
      }
    }
  }

  if (fs.existsSync(root)) {
    for await (const f of getFiles(root)) {
      fac[f.substring(root.length)] = {
        [extractAction]: fs.readFileSync(f).toString("utf8"),
      };
    }
  }

  return fac;
};

describe("os release parsing", () => {
  it("should parse os release files correctly", async () => {
    const examples = {
      "alpine:2.6": {
        dir: "alpine_2_6_6",
        extractActon: "alpine-release",
        expected: { name: "alpine", version: "2.6.6", prettyName: "" },
      },
      "alpine:3.7": {
        dir: "alpine_3_7_0",
        extractActon: "os-release",
        expected: {
          name: "alpine",
          version: "3.7.0",
          prettyName: "Alpine Linux v3.7",
        },
      },
      "centos:5": {
        dir: "centos_5",
        extractActon: "redhat-release",
        expected: { name: "centos", version: "5", prettyName: "" },
      },
      "centos:6": {
        dir: "centos_6",
        extractActon: "redhat-release",
        expected: { name: "centos", version: "6", prettyName: "" },
      },
      "centos:7": {
        dir: "centos_7",
        extractActon: "os-release",
        expected: {
          name: "centos",
          version: "7",
          prettyName: "CentOS Linux 7 (Core)",
        },
      },
      "debian:6": {
        dir: "debian_6",
        extractActon: "debian-version",
        expected: { name: "debian", version: "6", prettyName: "" },
      },
      "debian:7": {
        dir: "debian_7",
        extractActon: "os-release",
        expected: {
          name: "debian",
          version: "7",
          prettyName: "Debian GNU/Linux 7 (wheezy)",
        },
      },
      "debian:8": {
        dir: "debian_8",
        extractActon: "os-release",
        expected: {
          name: "debian",
          version: "8",
          prettyName: "Debian GNU/Linux 8 (jessie)",
        },
      },
      "debian:9": {
        dir: "debian_9",
        extractActon: "os-release",
        expected: {
          name: "debian",
          version: "9",
          prettyName: "Debian GNU/Linux 9 (stretch)",
        },
      },
      "debian:unstable": {
        dir: "debian_unstable",
        extractActon: "os-release",
        expected: {
          name: "debian",
          version: "unstable",
          prettyName: "Debian GNU/Linux buster/sid",
        },
      },
      "oracle:5.11": {
        dir: "oraclelinux_5_11",
        extractActon: "oracle-release",
        expected: { name: "oracle", version: "5", prettyName: "" },
      },
      "oracle:6.9": {
        dir: "oraclelinux_6_9",
        extractActon: "os-release",
        expected: {
          name: "oracle",
          version: "6",
          prettyName: "Oracle Linux Server 6.9",
        },
      },
      "oracle:7.5": {
        dir: "oraclelinux_7_5",
        extractActon: "os-release",
        expected: {
          name: "oracle",
          version: "7",
          prettyName: "Oracle Linux Server 7.5",
        },
      },
      "ubuntu:10.04": {
        dir: "ubuntu_10_04",
        extractActon: "lsb-release",
        expected: { name: "ubuntu", version: "10.04", prettyName: "" },
      },
      "ubuntu:12.04": {
        dir: "ubuntu_12_04",
        extractActon: "os-release",
        expected: {
          name: "ubuntu",
          version: "12.04",
          prettyName: "Ubuntu precise (12.04.5 LTS)",
        },
      },
      "ubuntu:14.04": {
        dir: "ubuntu_14_04",
        extractActon: "os-release",
        expected: {
          name: "ubuntu",
          version: "14.04",
          prettyName: "Ubuntu 14.04.5 LTS",
        },
      },
      "ubuntu:16.04": {
        dir: "ubuntu_16_04",
        extractActon: "os-release",
        expected: {
          name: "ubuntu",
          version: "16.04",
          prettyName: "Ubuntu 16.04.4 LTS",
        },
      },
      "ubuntu:18.04": {
        dir: "ubuntu_18_04",
        extractActon: "os-release",
        expected: {
          name: "ubuntu",
          version: "18.04",
          prettyName: "Ubuntu 18.04 LTS",
        },
      },
      scratch: {
        dir: "",
        expected: { name: "scratch", version: "0.0", prettyName: "" },
        dockerfileAnalysis: {
          baseImage: "scratch",
          dockerfilePackages: [],
        },
      },
      "unexpected:unexpected": {
        dir: "missing",
        expected: { name: "unknown", version: "0.0", prettyName: "" },
      },
      "sles:15": {
        dir: "sles_15",
        extractActon: "os-release",
        expected: {
          name: "sles",
          version: "15.0",
          prettyName: "SUSE Linux Enterprise Server 15",
        },
      },
      "redhat:6.5": {
        dir: "redhat_6_5",
        extractActon: "redhat-release",
        expected: {
          name: "rhel",
          version: "6",
          prettyName: "",
        },
      },
      "redhat:7.0": {
        dir: "redhat_7",
        extractActon: "redhat-release",
        expected: {
          name: "rhel",
          version: "7",
          prettyName: "",
        },
      },
    };

    for (const targetImage of Object.keys(examples)) {
      const example = examples[targetImage];
      const extractedLayers = await getOsFixtureFiles(
        example.dir,
        example.extractActon,
      );
      const res = await detect(extractedLayers, example.dockerfileAnalysis);

      expect(res).toEqual(example.expected);
    }
  });
});

describe("OS Release Analyzer functions", () => {
  describe("tryOSRelease", () => {
    it("should return null for empty text", async () => {
      const { tryOSRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const result = await tryOSRelease("");
      expect(result).toBeNull();
    });

    it("should throw error when ID is missing", async () => {
      const { tryOSRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "VERSION_ID=20.04\nPRETTY_NAME=Ubuntu";
      await expect(tryOSRelease(text)).rejects.toThrow(
        "Failed to parse /etc/os-release",
      );
    });

    it("should handle os-release without VERSION_ID", async () => {
      const { tryOSRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = 'ID=debian\nNAME="Debian GNU/Linux"';
      const result = await tryOSRelease(text);

      expect(result).toEqual({
        name: "debian",
        version: "unstable",
        prettyName: "",
      });
    });

    it("should handle Oracle Linux version parsing", async () => {
      const { tryOSRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text =
        'ID="ol"\nVERSION_ID="8.3.2011"\nPRETTY_NAME="Oracle Linux Server 8.3"';
      const result = await tryOSRelease(text);

      expect(result).toEqual({
        name: "ol",
        version: "8", // Should only take major version
        prettyName: "Oracle Linux Server 8.3",
      });
    });

    it("should handle quotes in values", async () => {
      const { tryOSRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text =
        'ID="ubuntu"\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.1 LTS"';
      const result = await tryOSRelease(text);

      expect(result).toEqual({
        name: "ubuntu",
        version: "20.04",
        prettyName: "Ubuntu 20.04.1 LTS",
      });
    });
  });

  describe("tryLsbRelease", () => {
    it("should return null for empty text", async () => {
      const { tryLsbRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const result = await tryLsbRelease("");
      expect(result).toBeNull();
    });

    it("should throw error when DISTRIB_ID is missing", async () => {
      const { tryLsbRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "DISTRIB_RELEASE=20.04";
      await expect(tryLsbRelease(text)).rejects.toThrow(
        "Failed to parse /etc/lsb-release",
      );
    });

    it("should throw error when DISTRIB_RELEASE is missing", async () => {
      const { tryLsbRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "DISTRIB_ID=Ubuntu";
      await expect(tryLsbRelease(text)).rejects.toThrow(
        "Failed to parse /etc/lsb-release",
      );
    });

    it("should parse lsb-release correctly", async () => {
      const { tryLsbRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text =
        "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=20.04\nDISTRIB_CODENAME=focal";
      const result = await tryLsbRelease(text);

      expect(result).toEqual({
        name: "ubuntu",
        version: "20.04",
        prettyName: "",
      });
    });

    it("should convert name to lowercase", async () => {
      const { tryLsbRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = 'DISTRIB_ID="UBUNTU"\nDISTRIB_RELEASE="18.04"';
      const result = await tryLsbRelease(text);

      expect(result?.name).toBe("ubuntu");
    });
  });

  describe("tryDebianVersion", () => {
    it("should return null for empty text", async () => {
      const { tryDebianVersion } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const result = await tryDebianVersion("");
      expect(result).toBeNull();
    });

    it("should throw error for very short version", async () => {
      const { tryDebianVersion } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "9";
      await expect(tryDebianVersion(text)).rejects.toThrow(
        "Failed to parse /etc/debian_version",
      );
    });

    it("should parse debian version correctly", async () => {
      const { tryDebianVersion } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "10.7";
      const result = await tryDebianVersion(text);

      expect(result).toEqual({
        name: "debian",
        version: "10",
        prettyName: "",
      });
    });

    it("should handle version with slash", async () => {
      const { tryDebianVersion } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "bullseye/sid";
      const result = await tryDebianVersion(text);

      expect(result).toEqual({
        name: "debian",
        version: "bullseye/sid", // No dot in string, so returns whole string
        prettyName: "",
      });
    });

    it("should trim whitespace", async () => {
      const { tryDebianVersion } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "  11.2  \n";
      const result = await tryDebianVersion(text);

      expect(result?.version).toBe("11");
    });
  });

  describe("tryAlpineRelease", () => {
    it("should return null for empty text", async () => {
      const { tryAlpineRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const result = await tryAlpineRelease("");
      expect(result).toBeNull();
    });

    it("should parse alpine version correctly", async () => {
      const { tryAlpineRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "3.14.0";
      const result = await tryAlpineRelease(text);

      expect(result).toEqual({
        name: "alpine",
        version: "3.14.0",
        prettyName: "",
      });
    });

    it("should handle version with newline", async () => {
      const { tryAlpineRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "3.13.5\n";
      const result = await tryAlpineRelease(text);

      expect(result?.version).toBe("3.13.5");
    });
  });

  describe("tryRedHatRelease", () => {
    it("should return null for empty text", async () => {
      const { tryRedHatRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const result = await tryRedHatRelease("");
      expect(result).toBeNull();
    });

    it("should throw error for unparseable format", async () => {
      const { tryRedHatRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "Invalid format";
      await expect(tryRedHatRelease(text)).rejects.toThrow(
        "Failed to parse /etc/redhat-release",
      );
    });

    it("should parse Red Hat release correctly", async () => {
      const { tryRedHatRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "Red Hat Enterprise Linux Server release 7.9 (Maipo)";
      const result = await tryRedHatRelease(text);

      expect(result).toEqual({
        name: "rhel",
        version: "7", // Only major version is extracted
        prettyName: "",
      });
    });

    it("should handle different Red Hat format", async () => {
      const { tryRedHatRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "Red Hat Enterprise Linux release 8.3 (Ootpa)";
      const result = await tryRedHatRelease(text);

      expect(result?.version).toBe("8"); // Only major version is extracted
    });
  });

  describe("tryCentosRelease", () => {
    it("should return null for empty text", async () => {
      const { tryCentosRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const result = await tryCentosRelease("");
      expect(result).toBeNull();
    });

    it("should throw error for unparseable format", async () => {
      const { tryCentosRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "Invalid CentOS format";
      await expect(tryCentosRelease(text)).rejects.toThrow(
        "Failed to parse /etc/centos-release",
      );
    });

    it("should parse CentOS release correctly", async () => {
      const { tryCentosRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "CentOS Linux release 7.9.2009 (Core)";
      const result = await tryCentosRelease(text);

      expect(result).toEqual({
        name: "centos",
        version: "7", // Only major version is extracted
        prettyName: "",
      });
    });
  });

  describe("tryOracleRelease", () => {
    it("should return null for empty text", async () => {
      const { tryOracleRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const result = await tryOracleRelease("");
      expect(result).toBeNull();
    });

    it("should throw error for unparseable format", async () => {
      const { tryOracleRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "Invalid Oracle format";
      await expect(tryOracleRelease(text)).rejects.toThrow(
        "Failed to parse /etc/oracle-release",
      );
    });

    it("should parse Oracle Linux release correctly", async () => {
      const { tryOracleRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "Oracle Linux Server release 8.3";
      const result = await tryOracleRelease(text);

      expect(result).toEqual({
        name: "oracle",
        version: "8", // Only major version is extracted
        prettyName: "",
      });
    });

    it("should handle Oracle Linux with extra info", async () => {
      const { tryOracleRelease } = await import(
        "../../../lib/analyzer/os-release/release-analyzer"
      );
      const text = "Oracle Linux Server release 7.9";
      const result = await tryOracleRelease(text);

      expect(result?.name).toBe("oracle");
      expect(result?.version).toBe("7"); // Only major version is extracted
    });
  });
});
