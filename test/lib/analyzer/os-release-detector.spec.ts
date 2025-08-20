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
