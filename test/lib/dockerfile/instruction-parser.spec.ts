import { DockerfileParser } from "dockerfile-ast";
import {
  getDockerfileBaseImageName,
  getPackagesFromDockerfile,
  instructionDigest,
} from "../../../lib/dockerfile";
import {
  getLayersFromPackages,
  getPackagesFromRunInstructions,
} from "../../../lib/dockerfile/instruction-parser";

describe("dockerfile instruction parser", () => {
  it("extracts packages from RUN install commands (apt, apk, yum, rpm)", () => {
    const content = [
      "FROM alpine:3.18",
      "RUN apk add --no-cache curl wget",
      "RUN apt-get install -y git ca-certificates",
      "RUN yum install nano",
      "RUN rpm -i somepkg",
    ].join("\n");

    const df = DockerfileParser.parse(content);
    const pkgs = getPackagesFromDockerfile(df);

    // keys are package names (no versions/flags)
    expect(Object.keys(pkgs)).toEqual(
      expect.arrayContaining([
        "curl",
        "wget",
        "git",
        "ca-certificates",
        "nano",
        "somepkg",
      ]),
    );
    // each entry contains original instruction and the matched install command
    expect(pkgs.curl.instruction).toContain("RUN apk add");
    expect(pkgs.git.installCommand).toMatch(/apt-get\s+install/);
  });

  it("handles BuildKit-style RUN prefix (args prefix) when extracting packages", () => {
    // exercises argsPrefixRegex path in cleanInstruction
    const runInstructions = [
      "RUN |1 foo=bar apt-get install -y make",
      "RUN |2 a=b apk add bash",
    ];
    const pkgs = getPackagesFromRunInstructions(runInstructions);

    expect(Object.keys(pkgs)).toEqual(expect.arrayContaining(["make", "bash"]));
  });

  it("builds layers from packages and digests map to original instruction", () => {
    const instruction = "RUN apt install curl";
    const pkgs = {
      curl: { instruction, installCommand: "apt install curl" },
    } as any;

    const layers = getLayersFromPackages(pkgs);
    const digest = instructionDigest(instruction);
    expect(layers[digest]).toEqual({ instruction });
  });

  it("resolves base image name for simple dockerfile", () => {
    const df = DockerfileParser.parse("FROM node:20-alpine\nRUN echo hi\n");
    const base = getDockerfileBaseImageName(df);
    expect(base.baseImage).toBe("node:20-alpine");
    expect(base.error).toBeUndefined();
  });
});
