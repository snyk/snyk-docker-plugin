import * as path from "path";
import { test } from "tap";
import { getDockerArchiveLayersAndManifest } from "../../../lib/extractor";
import { extractOciArchive } from "../../../lib/extractor/layer";
import { ExtractAction } from "../../../lib/extractor/types";
import { streamToString } from "../../../lib/stream-utils";

const getFixture = (fixturePath) =>
  path.join(__dirname, "../../fixtures", fixturePath);

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
    getFixture("docker-archives/docker-save/nginx.tar"),
    extractActions,
  );

  // Try a skopeo docker-archive
  await getDockerArchiveLayersAndManifest(
    getFixture("docker-archives/skopeo-copy/nginx.tar"),
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
    getFixture("docker-archives/docker-save/nginx.tar"),
    extractActions,
  );

  // Try a skopeo docker-archive
  await getDockerArchiveLayersAndManifest(
    getFixture("docker-archives/skopeo-copy/nginx.tar"),
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
    getFixture("docker-archives/skopeo-copy/nginx.tar"),
    extractActions,
  );

  const skopeoResult = await getDockerArchiveLayersAndManifest(
    getFixture("docker-archives/skopeo-copy/nginx.tar"),
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

test("oci image extractor: extracted image content returned as expected", async (t) => {
  const returnedContent =
    '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:e26d615025f594002683ea9b0104aeb886e0c383fcf96f9e372491beb17678e6","size":971}]}';
  const fileNamePattern = "/snyk/mock.json";
  const actionName = "read_as_string";

  const extractActions: ExtractAction[] = [
    {
      actionName: "read_as_string",
      filePathMatches: (filePath) => filePath === fileNamePattern,
      callback: async (stream) => {
        const content = await streamToString(stream);
        t.same(
          content,
          returnedContent,
          "Callback is issued when files are found",
        );
        return content;
      },
    },
  ];

  const result = await extractOciArchive(
    getFixture("oci-archives/nginx.tar"),
    extractActions,
  );

  t.ok(
    "layers" in result && "manifest" in result,
    "Result has expected structure",
  );

  const layer = result.layers[0];
  t.ok(
    fileNamePattern in layer &&
      actionName in layer[fileNamePattern] &&
      layer[fileNamePattern][actionName] === returnedContent,
    "The layers returned are as expected",
  );

  const manifest = result.manifest;

  t.deepEqual(
    manifest.layers.map((layer) => layer.digest),
    [
      "sha256:dd3ac8106a0bbe43a6e55d2b719fc00a2f8f694e90c7903403e8fdecd2ccc57f",
      "sha256:8de28bdda69b66a8e07b14f03a9762f508bc4caac35cef9543bad53503ce5f53",
      "sha256:a2c431ac2669038db7a758a597c7d1d53cdfb2dd9bf6de2ad3418973569b3fc7",
      "sha256:e070d03fd1b5a05aafc7c16830d80b4ed622d546061fabac8163d3082098a849",
    ],
    "Manifest returns expected layers content",
  );
});
