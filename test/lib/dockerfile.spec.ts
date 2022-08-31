import exp from "constants";
import * as path from "path";

import * as dockerFile from "../../lib/dockerfile";
import {
  DockerFileLayers,
  DockerFilePackages,
} from "../../lib/dockerfile/types";

interface TestCase {
  fixture: string;
  expected: {
    baseImage: string;
    dockerfilePackages: Record<string, Partial<DockerFilePackages[0]>>;
    dockerfileLayers: DockerFileLayers;
    error: undefined | Record<string, string>;
  };
}
type TestCaseTuple = [string, TestCase];

const getDockerfileFixture = (folder: string) =>
  path.join(__dirname, "../fixtures/dockerfiles", folder, "Dockerfile");

describe("readDockerfileAndAnalyse()", () => {
  test("returns undefined when Dockerfile is not supplied", async () => {
    const result = await dockerFile.readDockerfileAndAnalyse();
    expect(result).toBeUndefined();
  });
  test("rejects with ENOENT error when Dockerfile is not found", async () => {
    expect.assertions(1);
    await expect(
      dockerFile.readDockerfileAndAnalyse("missing/Dockerfile"),
    ).rejects.toThrowError("ENOENT: no such file or directory");
  });
});

describe("readDockerfileAndAnalyse() correctly parses...", () => {
  const cases: TestCaseTuple[] = [
    [
      "a simple Dockerfile",
      {
        fixture: "simple",
        expected: {
          baseImage: "ubuntu:bionic",
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: undefined,
        },
      },
    ],
    [
      "a multi-stage Dockerfile",
      {
        fixture: "multi-stage",
        expected: {
          baseImage: "alpine:latest",
          dockerfilePackages: {
            "ca-certificates": {
              instruction: "RUN apk --no-cache add ca-certificates",
            },
          },
          dockerfileLayers: {
            "UlVOIGFwayAtLW5vLWNhY2hlIGFkZCBjYS1jZXJ0aWZpY2F0ZXM=": {
              instruction: "RUN apk --no-cache add ca-certificates",
            },
          },
          error: undefined,
        },
      },
    ],
    [
      "a multi-stage Dockerfile with nested stages name referral",
      {
        fixture: "multi-stage-as",
        expected: {
          baseImage: "alpine:latest",
          dockerfilePackages: {
            "ca-certificates": {
              instruction: "RUN apk --no-cache add ca-certificates",
            },
          },
          dockerfileLayers: {
            "UlVOIGFwayAtLW5vLWNhY2hlIGFkZCBjYS1jZXJ0aWZpY2F0ZXM=": {
              instruction: "RUN apk --no-cache add ca-certificates",
            },
          },
          error: undefined,
        },
      },
    ],
    [
      "a multi-stage Dockerfile with args",
      {
        fixture: "multi-stage-with-args",
        expected: {
          baseImage: "node:6-slim",
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: undefined,
        },
      },
    ],
    [
      "a from-scratch Dockerfile",
      {
        fixture: "from-scratch",
        expected: {
          baseImage: "scratch",
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: undefined,
        },
      },
    ],
    [
      "an empty Dockerfile",
      {
        fixture: "empty",
        expected: {
          baseImage: undefined,
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: {
            code: "BASE_IMAGE_NAME_NOT_FOUND",
          },
        },
      },
    ],
    [
      "an invalid Dockerfile",
      {
        fixture: "invalid",
        expected: {
          baseImage: undefined,
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: {
            code: "BASE_IMAGE_NAME_NOT_FOUND",
          },
        },
      },
    ],
    [
      "a Dockerfile with multiple ARGs",
      {
        fixture: "with-args",
        expected: {
          baseImage: "node:dubnium",
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: undefined,
        },
      },
    ],
    [
      "a Dockerfile with multiple ARGs no curly braces",
      {
        fixture: "with-args-nobraces",
        expected: {
          baseImage: "node:dubnium",
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: undefined,
        },
      },
    ],
    [
      "a Dockerfile with multiple ARGs and multiple occurrences",
      {
        fixture: "with-args-occurences",
        expected: {
          baseImage: "test:test-1",
          dockerfilePackages: {},
          dockerfileLayers: {},
          error: undefined,
        },
      },
    ],
    [
      "a Dockerfile with ARG for package",
      {
        fixture: "with-args-package",
        expected: {
          baseImage: "ruby:2.5-alpine",
          dockerfilePackages: {
            bash: {
              instruction:
                "RUN apk update && apk upgrade && apk add --update --no-cache nodejs bash",
            },
            nodejs: {
              instruction:
                "RUN apk update && apk upgrade && apk add --update --no-cache nodejs bash",
            },
          },
          dockerfileLayers: {
            UlVOIGFwayB1cGRhdGUgJiYgYXBrIHVwZ3JhZGUgJiYgYXBrIGFkZCAtLXVwZGF0ZSAtLW5vLWNhY2hlIG5vZGVqcyBiYXNo:
              {
                instruction:
                  "RUN apk update && apk upgrade && apk add --update --no-cache nodejs bash",
              },
          },
          error: undefined,
        },
      },
    ],
    [
      "a Dockerfile with an installation instruction",
      {
        fixture: "with-installation-instruction",
        expected: {
          baseImage: "ubuntu:bionic",
          dockerfileLayers: {
            UlVOIGFwdC1nZXQgaW5zdGFsbCBjdXJs: {
              instruction: "RUN apt-get install curl",
            },
          },
          dockerfilePackages: {
            curl: {
              instruction: "RUN apt-get install curl",
            },
          },
          error: undefined,
        },
      },
    ],
    [
      "multi stage Dockerfile with lowercase instructions",
      {
        fixture: "multi-stage-lowercase",
        expected: {
          baseImage: "alpine:latest",
          dockerfilePackages: {
            "ca-certificates": {
              instruction: "RUN apk --no-cache add ca-certificates",
            },
          },
          dockerfileLayers: {
            "UlVOIGFwayAtLW5vLWNhY2hlIGFkZCBjYS1jZXJ0aWZpY2F0ZXM=": {
              instruction: "RUN apk --no-cache add ca-certificates",
            },
          },
          error: undefined,
        },
      },
    ],
  ];
  // tslint:disable-next-line: variable-name
  test.each<TestCaseTuple>(cases)("%s", async (_description, item) => {
    const { fixture, expected } = item;
    const pathToDockerFile = getDockerfileFixture(fixture);
    const actual = await dockerFile.readDockerfileAndAnalyse(pathToDockerFile);
    expect(actual.baseImage).toEqual(expected.baseImage);
    expect(actual.error).toEqual(expected.error);
    Object.keys(expected.dockerfilePackages).forEach((pkg) => {
      expect(actual.dockerfilePackages[pkg]).toEqual(
        expect.objectContaining({
          instruction: expected.dockerfilePackages[pkg].instruction,
        }),
      );
      expect(
        actual.dockerfilePackages[pkg].installCommand,
      ).toBeDockerPackageInstallCommand(pkg);
    });
    Object.keys(expected.dockerfileLayers).forEach((digest) => {
      expect(actual.dockerfileLayers[digest]).toEqual(
        expected.dockerfileLayers[digest],
      );
    });
  });
});
