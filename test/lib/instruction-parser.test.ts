import { DockerfileParser } from "dockerfile-ast";
import { test } from "tap";
import { getPackagesFromRunInstructions } from "../../lib/dockerfile";

const getDockerfile = (instructions: string[]) =>
  DockerfileParser.parse(["FROM test", ...instructions].join("\n"));

const removeSequentialSpaces = (str: string) => str.replace(/\s+/g, " ").trim();

test("instruction parsers", async (t) => {
  await t.test("getPackagesFromRunInstructions", async (t) => {
    await t.test('supports "apt install"', async (t) => {
      const instruction = "RUN apt install curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "apt-get install"', async (t) => {
      const instruction = "RUN apt-get install curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "apt-get install" with flags', async (t) => {
      const instruction = "RUN apt-get -y install curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "aptitude install"', async (t) => {
      const instruction = "RUN aptitude install curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "yum install"', async (t) => {
      const instruction = "RUN yum install curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "apk add"', async (t) => {
      const instruction = "RUN apk add curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "apk add" with flags', async (t) => {
      const instruction = "RUN apk --update add curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "rpm -i"', async (t) => {
      const instruction = "RUN rpm -i curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "rpm --install"', async (t) => {
      const instruction = "RUN rpm --install curl";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, { curl: { instruction } });
    });

    await t.test("handles an empty instruction", async (t) => {
      const instruction = "RUN ";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {});
    });

    await t.test("ignores irrelevant flags", async (t) => {
      const instruction = "RUN apt-get install -y wget curl -V";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {
        curl: { instruction },
        wget: { instruction },
      });
    });

    await t.test("handles multiple spaces", async (t) => {
      const instruction = "RUN    apt   install   curl   vim   ";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {
        curl: { instruction: removeSequentialSpaces(instruction) },
        vim: { instruction: removeSequentialSpaces(instruction) },
      });
    });

    await t.test("handles multiple lines", async (t) => {
      const instruction = "RUN apt install curl  vim";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {
        curl: { instruction: removeSequentialSpaces(instruction) },
        vim: { instruction: removeSequentialSpaces(instruction) },
      });
    });

    await t.test("returns multiple packages", async (t) => {
      const instruction = "RUN apt install curl wget vim";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {
        curl: { instruction },
        wget: { instruction },
        vim: { instruction },
      });
    });

    await t.test('supports multiple commands using "&&"', async (t) => {
      const instruction = "RUN apt install curl && apt install wget";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {
        curl: { instruction: removeSequentialSpaces(instruction) },
        wget: { instruction: removeSequentialSpaces(instruction) },
      });
    });

    await t.test('supports multiple commands using ";"', async (t) => {
      const instruction =
        'RUN apt install curl; apt install vim; echo "bitwise"';
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {
        curl: { instruction },
        vim: { instruction },
      });
    });

    await t.test(
      "complex case: multiple instructions with multiple commands",
      async (t) => {
        const instructionOne = "RUN apt install curl && apt       install vim";
        const instructionTwo = "RUN apt install   -y  wget";
        const packages = getPackagesFromRunInstructions(
          getDockerfile([instructionOne, instructionTwo]),
        );

        t.same(packages, {
          curl: { instruction: removeSequentialSpaces(instructionOne) },
          vim: { instruction: removeSequentialSpaces(instructionOne) },
          wget: { instruction: removeSequentialSpaces(instructionTwo) },
        });
      },
    );

    await t.test('supports "-" in pkg name', async (t) => {
      const instruction = "RUN apt install 389-admin";
      const packages = getPackagesFromRunInstructions(
        getDockerfile([instruction]),
      );

      t.same(packages, {
        "389-admin": { instruction },
      });
    });
  });
});
