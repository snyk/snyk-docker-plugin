import { DockerfileParser } from "dockerfile-ast";
import { EOL } from "os";
import { getDockerfileBaseImageName } from "../../../lib/dockerfile";

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
