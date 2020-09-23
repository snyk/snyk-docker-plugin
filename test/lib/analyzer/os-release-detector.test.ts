// tslint:disable:max-line-length
// tslint:disable:no-string-throw

import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";

import * as osReleaseDetector from "../../../lib/analyzer/os-release";
import * as archiveExtractor from "../../../lib/extractor/index";
import { getOsReleaseActions } from "../../../lib/inputs/os-release/static";
import * as subProcess from "../../../lib/sub-process";
import { ImageType } from "../../../lib/types";

const readOsFixtureFile = (...from) =>
  fs.readFileSync(path.join(__dirname, "../../fixtures/os", ...from), "utf8");

test("os release detection dynamically", async (t) => {
  const examples = {
    "alpine:2.6": {
      dir: "alpine_2_6_6",
      expected: { name: "alpine", version: "2.6.6", prettyName: "" },
      notes: "uses /etc/alpine-release",
    },
    "alpine:3.7": {
      dir: "alpine_3_7_0",
      expected: {
        name: "alpine",
        version: "3.7.0",
        prettyName: "Alpine Linux v3.7",
      },
      notes: "uses /etc/os-release",
    },
    "centos:5": {
      dir: "centos_5",
      expected: { name: "centos", version: "5", prettyName: "" },
      notes: "uses /etc/redhat-release",
    },
    "centos:6": {
      dir: "centos_6",
      expected: { name: "centos", version: "6", prettyName: "" },
      notes: "uses /etc/redhat-release",
    },
    "centos:7": {
      dir: "centos_7",
      expected: {
        name: "centos",
        version: "7",
        prettyName: "CentOS Linux 7 (Core)",
      },
      notes: "uses /etc/os-release",
    },
    "debian:6": {
      dir: "debian_6",
      expected: { name: "debian", version: "6", prettyName: "" },
      notes: "uses /etc/debian_version",
    },
    "debian:7": {
      dir: "debian_7",
      expected: {
        name: "debian",
        version: "7",
        prettyName: "Debian GNU/Linux 7 (wheezy)",
      },
      notes: "uses /etc/os-release",
    },
    "debian:8": {
      dir: "debian_8",
      expected: {
        name: "debian",
        version: "8",
        prettyName: "Debian GNU/Linux 8 (jessie)",
      },
      notes: "uses /etc/os-release",
    },
    "debian:9": {
      dir: "debian_9",
      expected: {
        name: "debian",
        version: "9",
        prettyName: "Debian GNU/Linux 9 (stretch)",
      },
      notes: "uses /etc/os-release",
    },
    "debian:unstable": {
      dir: "debian_unstable",
      expected: {
        name: "debian",
        version: "unstable",
        prettyName: "Debian GNU/Linux buster/sid",
      },
      notes: "uses /etc/os-release",
    },
    "oracle:5.11": {
      dir: "oraclelinux_5_11",
      expected: { name: "oracle", version: "5", prettyName: "" },
      notes: "uses /etc/oracle-release",
    },
    "oracle:6.9": {
      dir: "oraclelinux_6_9",
      expected: {
        name: "oracle",
        version: "6",
        prettyName: "Oracle Linux Server 6.9",
      },
      notes: "uses /etc/os-release",
    },
    "oracle:7.5": {
      dir: "oraclelinux_7_5",
      expected: {
        name: "oracle",
        version: "7",
        prettyName: "Oracle Linux Server 7.5",
      },
      notes: "uses /etc/os-release",
    },
    "ubuntu:10.04": {
      dir: "ubuntu_10_04",
      expected: { name: "ubuntu", version: "10.04", prettyName: "" },
      notes: "uses /etc/lsb-release",
    },
    "ubuntu:12.04": {
      dir: "ubuntu_12_04",
      expected: {
        name: "ubuntu",
        version: "12.04",
        prettyName: "Ubuntu precise (12.04.5 LTS)",
      },
      notes: "uses /etc/os-release",
    },
    "ubuntu:14.04": {
      dir: "ubuntu_14_04",
      expected: {
        name: "ubuntu",
        version: "14.04",
        prettyName: "Ubuntu 14.04.5 LTS",
      },
      notes: "uses /etc/os-release",
    },
    "ubuntu:16.04": {
      dir: "ubuntu_16_04",
      expected: {
        name: "ubuntu",
        version: "16.04",
        prettyName: "Ubuntu 16.04.4 LTS",
      },
      notes: "uses /etc/os-release",
    },
    "ubuntu:18.04": {
      dir: "ubuntu_18_04",
      expected: {
        name: "ubuntu",
        version: "18.04",
        prettyName: "Ubuntu 18.04 LTS",
      },
      notes: "uses /etc/os-release",
    },
    scratch: {
      dir: "",
      expected: { name: "scratch", version: "0.0", prettyName: "" },
      notes: "uses dockerfile",
      dockerfileAnalysis: {
        baseImage: "scratch",
        dockerfilePackages: [],
      },
    },
    "unexpected:unexpected": {
      dir: "missing",
      expected: { name: "unknown", version: "0.0", prettyName: "" },
      notes: "when nothing is found",
    },
    "sles:15": {
      dir: "sles_15",
      expected: {
        name: "sles",
        version: "15.0",
        prettyName: "SUSE Linux Enterprise Server 15",
      },
      notes: "uses /etc/os-release",
    },
  };

  const execStub = sinon.stub(subProcess, "execute");
  execStub
    .withArgs("docker", [
      "run",
      "--rm",
      "--entrypoint",
      '""',
      "--network",
      "none",
      sinon.match.any,
      "cat",
      sinon.match.any,
    ])
    .callsFake(
      async (
        docker,
        [run, rm, entry, empty, network, none, image, cat, file],
      ) => {
        const example = examples[image];
        if (example.dir === "") {
          throw {
            stderr: `cat: ${file}: No such file or directory`,
            stdout: "",
          };
        }
        try {
          return {
            stdout: readOsFixtureFile(example.dir, "fs", file),
            stderr: "",
          };
        } catch {
          throw {
            stderr: `cat: ${file}: No such file or directory`,
            stdout: "",
          };
        }
      },
    );
  t.teardown(() => execStub.restore());

  for (const targetImage of Object.keys(examples)) {
    const example = examples[targetImage];
    const actual = await osReleaseDetector.detectDynamically(
      targetImage,
      example.dockerfileAnalysis,
    );
    t.same(actual, example.expected, targetImage);
  }
});

test("os release detection statically", async (t) => {
  const examples = {
    "centos:6": {
      dir: "centos",
      imageType: ImageType.DockerArchive,
      imagePath: path.join(
        __dirname,
        "../../fixtures/docker-archives/skopeo-copy/centos-6.tar",
      ),
      expected: { name: "centos", version: "6", prettyName: "" },
      notes: "uses /etc/centos-release",
    },
  };

  for (const targetImage of Object.keys(examples)) {
    const example = examples[targetImage];
    const { extractedLayers } = await archiveExtractor.extractImageContent(
      example.imageType,
      example.imagePath,
      getOsReleaseActions,
    );
    const actual = await osReleaseDetector.detectStatically(
      extractedLayers,
      undefined,
    );
    t.same(actual, example.expected, targetImage);
  }
});

test("failed detection", async (t) => {
  const examples = {
    "os-release:corrupt": {
      dir: "os_release_corrupt",
      expectedError: "Failed to parse /etc/os-release",
    },
    "lsb-release:corrupt": {
      dir: "lsb_release_corrupt",
      expectedError: "Failed to parse /etc/lsb-release",
    },
    "debian_version:corrupt": {
      dir: "debian_version_corrupt",
      expectedError: "Failed to parse /etc/debian_version",
    },
    "alpine-release:corrupt": {
      dir: "alpine_release_corrupt",
      expectedError: "Failed to parse /etc/alpine-release",
    },
  };

  const execStub = sinon.stub(subProcess, "execute");
  execStub
    .withArgs("docker", [
      "run",
      "--rm",
      "--entrypoint",
      '""',
      "--network",
      "none",
      sinon.match.any,
      "cat",
      sinon.match.any,
    ])
    .callsFake(
      async (
        docker,
        [run, rm, entry, empty, network, none, image, cat, file],
      ) => {
        try {
          const example = examples[image];
          return {
            stdout: readOsFixtureFile(example.dir, "fs", file),
            stderr: "",
          };
        } catch {
          throw {
            stderr: `cat: ${file}: No such file or directory`,
            stdout: "",
          };
        }
      },
    );
  t.teardown(() => execStub.restore());

  for (const targetImage of Object.keys(examples)) {
    const example = examples[targetImage];
    try {
      await osReleaseDetector.detectDynamically(targetImage);
      t.fail("should have thrown");
    } catch (error) {
      t.same(error.message, example.expectedError, example.expectedError);
    }
  }
});
