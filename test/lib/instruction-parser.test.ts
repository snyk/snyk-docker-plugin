#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { test } from "tap";
import { getPackagesFromRunInstructions } from "../../lib/instruction-parser";

test("instruction parsers", async (t) => {
  await t.test("getPackagesFromRunInstructions", async (t) => {
    await t.test('supports "apt install"', async (t) => {
      const instruction = "RUN apt install curl";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "apt-get install"', async (t) => {
      const instruction = "RUN apt-get install curl";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "aptitude install"', async (t) => {
      const instruction = "RUN aptitude install curl";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "yum install"', async (t) => {
      const instruction = "RUN yum install curl";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "apk add"', async (t) => {
      const instruction = "RUN apk add curl";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "rpm -i"', async (t) => {
      const instruction = "RUN rpm -i curl";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, { curl: { instruction } });
    });

    await t.test('supports "rpm --install"', async (t) => {
      const instruction = "RUN rpm --install curl";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, { curl: { instruction } });
    });

    await t.test("handles an empty instruction", async (t) => {
      const instruction = "RUN ";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, {});
    });

    await t.test("ignores irrelevant flags", async (t) => {
      const instruction = "RUN apt-get install -y wget curl -V";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, {
        curl: { instruction },
        wget: { instruction },
      });
    });

    await t.test("handles multiple spaces", async (t) => {
      const instruction = "RUN    apt   install   curl   vim   ";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, {
        curl: { instruction },
        vim: { instruction },
      });
    });

    await t.test("handles multiple lines", async (t) => {
      const instruction = "RUN apt install curl  vim";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, {
        curl: { instruction },
        vim: { instruction },
      });
    });

    await t.test("returns multiple packages", async (t) => {
      const instruction = "RUN apt install curl wget vim";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, {
        curl: { instruction },
        wget: { instruction },
        vim: { instruction },
      });
    });

    await t.test('supports multiple commands using "&&"', async (t) => {
      const instruction = "RUN apt install curl && apt install wget";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, {
        curl: { instruction },
        wget: { instruction },
      });
    });

    await t.test('supports multiple commands using ";"', async (t) => {
      const instruction =
        'RUN apt install curl; apt install vim; echo "bitwise"';
      const packages = getPackagesFromRunInstructions([instruction]);

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
        const packages = getPackagesFromRunInstructions([
          instructionOne,
          instructionTwo,
        ]);

        t.same(packages, {
          curl: { instruction: instructionOne },
          vim: { instruction: instructionOne },
          wget: { instruction: instructionTwo },
        });
      },
    );

    await t.test('supports "-" in pkg name', async (t) => {
      const instruction = "RUN apt install 389-admin";
      const packages = getPackagesFromRunInstructions([instruction]);

      t.same(packages, {
        "389-admin": { instruction },
      });
    });
  });
});
