import { DockerfileParser } from "dockerfile-ast";
import { EOL } from "os";
import {
  getDockerfileBaseImageName,
  updateDockerfileBaseImageName,
} from "../../../lib/dockerfile";
import {
  DockerFileAnalysisErrorCode,
  UpdateDockerfileBaseImageNameErrorCode,
} from "../../../lib/dockerfile/types";

describe("base image parsing", () => {
  it.each`
    dockerfile
    ${""}
    ${"ARG A"}
    ${"# FROM image:tag"}
  `("does not detect missing base image: $dockerfile", ({ dockerfile }) => {
    const result = getDockerfileBaseImageName(
      DockerfileParser.parse(dockerfile),
    );

    expect(result.baseImage).toBeUndefined();
    expect(result).toEqual({
      error: {
        code: DockerFileAnalysisErrorCode.BASE_IMAGE_NAME_NOT_FOUND,
      },
    });
  });

  it.each`
    dockerfile
    ${"FROM ${A}:${B}"}
    ${"FROM ${A}@${B}"}
    ${"FROM image@${B}"}
    ${"FROM ${DOCKER_BASE_REGISTRY}/image"}
    ${"FROM ${DOCKER_BASE_REGISTRY}/image:tag"}
    ${"ARG A" + EOL + "ARG B" + EOL + "FROM ${A}:${B}"}
    ${"ARG A" + EOL + "FROM ${A}:tag"}
    ${"ARG B" + EOL + "FROM alpine:${B}"}
    ${"ARG A" + EOL + "ARG B" + EOL + "FROM ${A}:${B} AS image"}
  `("does not detect injected base image: $dockerfile", ({ dockerfile }) => {
    const result = getDockerfileBaseImageName(
      DockerfileParser.parse(dockerfile),
    );

    expect(result.baseImage).toBeUndefined();
    expect(result).toEqual({
      error: {
        code: DockerFileAnalysisErrorCode.BASE_IMAGE_NON_RESOLVABLE,
      },
    });
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
    const result = getDockerfileBaseImageName(
      DockerfileParser.parse(dockerfile),
    );
    expect(result.baseImage).toBeDefined();
    expect(result.error).toBeUndefined();
  });
});

describe("base image updating", () => {
  describe("single stage", () => {
    it.each`
      scenario        | content                                          | expected
      ${"basic"}      | ${"FROM repo"}                                   | ${"FROM repo:tag0"}
      ${"with alias"} | ${"FROM repo:tag1 AS BASE"}                      | ${"FROM repo:tag0 AS BASE"}
      ${"with arg"}   | ${"ARG IMAGE=repo:tag1" + EOL + "FROM ${IMAGE}"} | ${"ARG IMAGE=repo:tag0" + EOL + "FROM ${IMAGE}"}
      ${"with tag"}   | ${"FROM repo:tag1"}                              | ${"FROM repo:tag0"}
    `("updates base image: $scenario", ({ content, expected }) => {
      const result = updateDockerfileBaseImageName(content, "repo:tag0");
      expect(result.error).toBeUndefined();
      expect(result.contents).toBe(expected);
    });
  });

  describe("multi stage", () => {
    it.each`
      scenario                        | content                                                                   | expected
      ${"basic"}                      | ${"FROM repo:tag2" + EOL + "FROM repo"}                                   | ${"FROM repo:tag2" + EOL + "FROM repo:tag0"}
      ${"with tag"}                   | ${"FROM repo:tag2" + EOL + "FROM repo:tag1"}                              | ${"FROM repo:tag2" + EOL + "FROM repo:tag0"}
      ${"duplicate"}                  | ${"FROM repo" + EOL + "FROM repo"}                                        | ${"FROM repo:tag0" + EOL + "FROM repo:tag0"}
      ${"duplicate with tag"}         | ${"FROM repo:tag1" + EOL + "FROM repo:tag1"}                              | ${"FROM repo:tag0" + EOL + "FROM repo:tag0"}
      ${"with arg"}                   | ${"ARG IMAGE=repo:tag1" + EOL + "FROM repo:tag2" + EOL + "FROM ${IMAGE}"} | ${"ARG IMAGE=repo:tag0" + EOL + "FROM repo:tag2" + EOL + "FROM ${IMAGE}"}
      ${"with non related arg"}       | ${"ARG IMAGE=repo:tag1" + EOL + "FROM ${IMAGE}" + EOL + "FROM repo:tag2"} | ${"ARG IMAGE=repo:tag1" + EOL + "FROM ${IMAGE}" + EOL + "FROM repo:tag0"}
      ${"with duplicate related arg"} | ${"ARG IMAGE=repo:tag1" + EOL + "FROM repo:tag1" + EOL + "FROM ${IMAGE}"} | ${"ARG IMAGE=repo:tag0" + EOL + "FROM repo:tag0" + EOL + "FROM ${IMAGE}"}
    `("updates base image: $scenario", ({ content, expected }) => {
      const result = updateDockerfileBaseImageName(content, "repo:tag0");
      expect(result.error).toBeUndefined();
      expect(result.contents).toBe(expected);
    });
  });

  describe("case sensitivity", () => {
    it.each`
      scenario        | content                     | expected
      ${"lowercase"}  | ${"from repo:tag1 as base"} | ${"from repo:tag0 as base"}
      ${"uppercase"}  | ${"FROM repo:tag1 AS BASE"} | ${"FROM repo:tag0 AS BASE"}
      ${"mixed case"} | ${"fRoM repo:tag1 aS bAsE"} | ${"fRoM repo:tag0 aS bAsE"}
    `("updates base image: $scenario", ({ content, expected }) => {
      const result = updateDockerfileBaseImageName(content, "repo:tag0");
      expect(result.error).toBeUndefined();
      expect(result.contents).toBe(expected);
    });
  });

  describe("comments", () => {
    it.each`
      scenario    | content                                                       | expected
      ${"before"} | ${"#FROM repo:tag1 AS BASE" + EOL + "FROM repo:tag1 AS BASE"} | ${"#FROM repo:tag1 AS BASE" + EOL + "FROM repo:tag0 AS BASE"}
      ${"after"}  | ${"FROM repo:tag1 AS BASE" + EOL + "#FROM repo:tag1 AS BASE"} | ${"FROM repo:tag0 AS BASE" + EOL + "#FROM repo:tag1 AS BASE"}
    `("does not update comment: $scenario", ({ content, expected }) => {
      const result = updateDockerfileBaseImageName(content, "repo:tag0");
      expect(result.error).toBeUndefined();
      expect(result.contents).toBe(expected);
    });
  });

  describe("whitespace", () => {
    it.each`
      scenario                    | content                       | expected
      ${"between from and image"} | ${"FROM   repo:tag1 AS BASE"} | ${"FROM   repo:tag0 AS BASE"}
      ${"between image and as"}   | ${"FROM repo:tag1   AS BASE"} | ${"FROM repo:tag0   AS BASE"}
      ${"between as and alias"}   | ${"FROM repo:tag1 AS   BASE"} | ${"FROM repo:tag0 AS   BASE"}
    `("does not update comment: $scenario", ({ content, expected }) => {
      const result = updateDockerfileBaseImageName(content, "repo:tag0");
      expect(result.error).toBeUndefined();
      expect(result.contents).toBe(expected);
    });
  });

  describe("unsupported cases", () => {
    it.each`
      scenario                                          | content
      ${"${REPO}:${TAG}"}                               | ${"ARG REPO=repo" + EOL + "ARG TAG=tag" + EOL + "FROM ${REPO}:${TAG}"}
      ${"${REPO}:${MAJOR}.${MINOR}.${PATCH}-${FLAVOR}"} | ${"ARG REPO=repo" + EOL + "ARG MAJOR=1" + EOL + "ARG MINOR=0" + EOL + "ARG PATCH=0" + EOL + "ARG FLAVOR=slim" + EOL + "FROM ${REPO}:${MAJOR}.${MINOR}.${PATCH}-${FLAVOR}"}
    `("does not update: $scenario", ({ content }) => {
      const result = updateDockerfileBaseImageName(content, "image:tag0");
      expect(result.error.code).toBe(
        UpdateDockerfileBaseImageNameErrorCode.BASE_IMAGE_NAME_FRAGMENTED,
      );
      expect(result.contents).toBe(content);
    });

    it.each`
      scenario            | content
      ${"malformed ARG"}  | ${"ARG_X IMAGE=repo:tag" + EOL + "FROM ${IMAGE}"}
      ${"malformed FROM"} | ${"FROM_X image:tag"}
      ${"missing ARG"}    | ${"FROM ${IMAGE}"}
      ${"missing FROM"}   | ${"#FROM image:tag"}
    `("does not update: $scenario", ({ content }) => {
      const result = updateDockerfileBaseImageName(content, "image:tag0");
      expect(result.error.code).toBe(
        UpdateDockerfileBaseImageNameErrorCode.BASE_IMAGE_NAME_NOT_FOUND,
      );
      expect(result.contents).toBe(content);
    });
  });
});
