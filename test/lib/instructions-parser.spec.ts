import { DockerfileParser } from "dockerfile-ast";
import { readFileSync } from "fs";
import { resolve } from "path";
import {
  getPackagesFromDockerfile,
  getPackagesFromRunInstructions,
} from "../../lib/dockerfile/instruction-parser";

describe("getPackagesFromRunInstructions", () => {
  const formatInstructions = (instructions: string[]): string[] =>
    instructions.map((instruction) => `RUN /bin/sh -c ${instruction}`);

  const cases = [
    [["apt install curl"], ["curl"]],
    [["apt-get install curl"], ["curl"]],
    [["apt-get -y install curl"], ["curl"]],
    [["aptitude install curl"], ["curl"]],
    [["yum install curl"], ["curl"]],
    [["apk add curl"], ["curl"]],
    [["apk --update add curl"], ["curl"]],
    [["rpm -i curl"], ["curl"]],
    [["rpm --install curl"], ["curl"]],
    [["apt-get install -y wget curl -V"], ["curl", "wget"]],
    [["    apt   install   curl   vim   "], ["curl", "vim"]],
    [["apt install curl  vim"], ["curl", "vim"]],
    [["apt install curl wget vim"], ["vim", "curl", "wget"]],
    [["apt install curl && apt install wget"], ["curl", "wget"]],
    [['apt install curl; apt install vim; echo "bitwise"'], ["curl", "vim"]],
    [
      ["apt install curl && apt       install vim", "apt install   -y  wget"],
      ["curl", "vim", "wget"],
    ],
    [["apt install 389-admin"], ["389-admin"]],
    [["apt install apache2=2.3.35-4ubuntu1"], ["apache2"]],
  ];

  describe("Verify package detection", () => {
    test.each(cases)(
      "given instructions %p, expect packages %p to be detected",
      (instructions: string[], expectedResult: string[]) => {
        const result = getPackagesFromRunInstructions(
          formatInstructions(instructions),
        );
        expect(Object.keys(result).sort()).toEqual(expectedResult.sort());
      },
    );
  });

  describe("Verify package install command", () => {
    test.each(cases)(
      "given instructions %p, expect packages %p to reference install command",
      (instructions: string[]) => {
        const results = getPackagesFromRunInstructions(
          formatInstructions(instructions),
        );
        Object.keys(results).forEach((pkgName) =>
          expect(
            results[pkgName].installCommand,
          ).toBeDockerPackageInstallCommand(pkgName),
        );
      },
    );
    test("given an image built with --build-arg flags, expect ARG values to be stripped from RUN instruction", () => {
      const instruction: string =
        "RUN |2 TEST_STRING_1=Test string one TEST_STRING_2=Test\nstring two /bin/sh -c apt install -y curl";
      const results = getPackagesFromRunInstructions([instruction]) as {
        [key: string]: Record<string, string>;
      };
      expect(results.curl.installCommand).toBeDockerPackageInstallCommand(
        "curl",
      );
    });
  });
});

describe("getPackagesFromDockerFile", () => {
  const dockerfileFixtures = [
    ["library/nginx"],
    ["with-args-package"],
    ["with-multiple-run-instructions"],
  ];

  test.each(dockerfileFixtures)(
    "given dockerFile fixture %p, expect all returned packages to reference install command",
    (fixture: string) => {
      const filePath = resolve(
        "test/fixtures/dockerfiles",
        fixture,
        "Dockerfile",
      );
      const content = readFileSync(filePath, "utf-8").toString();
      const dockerFile = DockerfileParser.parse(content);
      const results = getPackagesFromDockerfile(dockerFile);
      Object.keys(results).forEach((pkgName) =>
        expect(results[pkgName].installCommand).toBeDockerPackageInstallCommand(
          pkgName,
        ),
      );
    },
  );
});
