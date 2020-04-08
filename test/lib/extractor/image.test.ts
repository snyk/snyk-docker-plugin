#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as path from "path";
import { test } from "tap";
import { getDockerArchiveLayersAndManifest } from "../../../lib/extractor";
import { ExtractAction } from "../../../lib/extractor/types";
import { streamToString } from "../../../lib/stream-utils";

const getFixture = (fixturePath) =>
  path.join(__dirname, "../../fixtures/docker-archives", fixturePath);

test("image extractor: callbacks are issued when files are found", async (t) => {
  t.plan(2);

  const extractActions: ExtractAction[] = [
    {
      actionName: "read_as_string",
      filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
      callback: async (stream) => {
        const content = await streamToString(stream);
        t.same(content, "Hello, world!", "content read is as expected");
        return content;
      },
    },
  ];

  // Try a docker-archive first
  await getDockerArchiveLayersAndManifest(
    getFixture("docker-save/nginx.tar"),
    extractActions,
  );

  // Try a skopeo docker-archive
  await getDockerArchiveLayersAndManifest(
    getFixture("skopeo-copy/nginx.tar"),
    extractActions,
  );
});

test("image extractor: can read content with multiple callbacks", async (t) => {
  t.plan(4);

  const extractActions: ExtractAction[] = [
    {
      actionName: "read_as_string",
      filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
      callback: async (stream) => {
        const content = await streamToString(stream);
        t.same(content, "Hello, world!", "content read is as expected");
        return content;
      },
    },
    {
      actionName: "read_as_buffer",
      filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
      callback: async (stream) => {
        const content = await streamToString(stream);
        t.same(content, "Hello, world!", "content read is as expected");
        return `${content} Second callback!`;
      },
    },
  ];

  // Try a docker-archive first
  await getDockerArchiveLayersAndManifest(
    getFixture("docker-save/nginx.tar"),
    extractActions,
  );

  // Try a skopeo docker-archive
  await getDockerArchiveLayersAndManifest(
    getFixture("skopeo-copy/nginx.tar"),
    extractActions,
  );
});

test("image extractor: ensure the layer results are the same for docker and for skopeo docker-archives", async (t) => {
  const returnedContent = "this is a mock";
  const fileNamePattern = "/snyk/mock.txt";
  const actionName = "find_mock";

  const extractActions: ExtractAction[] = [
    {
      actionName,
      filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
      callback: async () => returnedContent,
    },
  ];

  const dockerResult = await getDockerArchiveLayersAndManifest(
    getFixture("skopeo-copy/nginx.tar"),
    extractActions,
  );

  const skopeoResult = await getDockerArchiveLayersAndManifest(
    getFixture("skopeo-copy/nginx.tar"),
    extractActions,
  );

  t.deepEqual(
    dockerResult,
    skopeoResult,
    "Docker and Skopeo docker-archive outputs resolve the same way",
  );

  t.ok(
    "layers" in dockerResult && "manifest" in dockerResult,
    "Returns the expected structure",
  );

  const layers = dockerResult.layers;
  t.ok(
    fileNamePattern in layers &&
      actionName in layers[fileNamePattern] &&
      layers[fileNamePattern][actionName] === returnedContent,
    "The layers returned are as expected",
  );

  const manifest = dockerResult.manifest;
  t.ok(
    "Config" in manifest && "Layers" in manifest && "RepoTags" in manifest,
    "The manifest contains the expected entries",
  );
  t.same(manifest.RepoTags, [], "RepoTags is empty");
  t.same(
    manifest.Config,
    "ab56bba91343aafcdd94b7a44b42e12f32719b9a2b8579e93017c1280f48e8f3.json",
    "Config matches",
  );
  t.deepEqual(
    manifest.Layers,
    ["ce3539cc184915f96add8551b0e7a37d80c560fe3ffe40cfe4585ea3a8dc14e9.tar"],
    "Layers match",
  );
});
