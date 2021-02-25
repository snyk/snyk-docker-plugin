import { DockerfileParser } from "dockerfile-ast";
import { EOL } from "os";
import {
  getDockerfileBaseImageName,
  updateDockerfileBaseImage,
} from "../../../lib/dockerfile";

describe("base image parsing", () => {
  it.each`
    dockerfile
    ${"FROM ${A}:${B}"}
    ${"FROM ${A}@${B}"}
    ${"FROM image@${B}"}
    ${"ARG A" + EOL + "ARG B" + EOL + "FROM ${A}:${B}"}
    ${"ARG A" + EOL + "FROM ${A}:tag"}
    ${"ARG B" + EOL + "FROM alpine:${B}"}
    ${"ARG A" + EOL + "ARG B" + EOL + "FROM ${A}:${B} AS image"}
  `("does not detect injected base image: $dockerfile", ({ dockerfile }) => {
    expect(
      getDockerfileBaseImageName(DockerfileParser.parse(dockerfile)),
    ).toBeUndefined();
  });

  it.each`
    dockerfile
    ${"FROM image"}
    ${"FROM image AS foo"}
    ${"FROM image:tag"}
    ${"FROM image:tag AS foo"}
    ${"FROM image@sha256:abcd"}
    ${"FROM image@sha256:abcd AS foo"}
  `("detects base image: $dockerfile", ({ dockerfile }) => {
    expect(
      getDockerfileBaseImageName(DockerfileParser.parse(dockerfile)),
    ).toBeDefined();
  });
});

describe("base image updating", () => {
  it.each`
    content                                                                     | expected
    ${"FROM image:tag1"}                                                        | ${"FROM image:tag0"}
    ${"FROM image:tag1" + EOL + "FROM image:tag1"}                              | ${"FROM image:tag0" + EOL + "FROM image:tag0"}
    ${"ARG IMAGE=image:tag1" + EOL + "FROM ${IMAGE}"}                           | ${"ARG IMAGE=image:tag0" + EOL + "FROM ${IMAGE}"}
    ${"ARG IMAGE=image:tag1" + EOL + "FROM ${IMAGE}" + EOL + "FROM image"}      | ${"ARG IMAGE=image:tag1" + EOL + "FROM ${IMAGE}" + EOL + "FROM image:tag0"}
    ${"ARG IMAGE=image:tag1" + EOL + "FROM image:tag2" + EOL + "FROM ${IMAGE}"} | ${"ARG IMAGE=image:tag0" + EOL + "FROM image:tag2" + EOL + "FROM ${IMAGE}"}
    ${"ARG IMAGE=image:tag1" + EOL + "FROM image:tag1" + EOL + "FROM ${IMAGE}"} | ${"ARG IMAGE=image:tag0" + EOL + "FROM image:tag0" + EOL + "FROM ${IMAGE}"}
  `("updates base image: $content", async ({ content, expected }) => {
    const actual = await updateDockerfileBaseImage(content, "image:tag0");
    expect(actual).toBe(expected);
  });
});
