import { getPackagesFromRunInstructions } from "../../lib/dockerfile/instruction-parser";

describe("instruction parser", () => {
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
  ];
  test.each(cases)(
    "given instructions %p, expect packages %p",
    (instructions: string[], expectedResult: string[]) => {
      const instructionFromConfigPrefix = "/bin/sh -c";
      const result = getPackagesFromRunInstructions(
        instructions.map(
          (instruction) => `${instructionFromConfigPrefix} ${instruction}`,
        ),
      );
      expect(Object.keys(result).sort()).toEqual(expectedResult.sort());
    },
  );
});
