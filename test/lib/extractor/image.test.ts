import { test } from "tap";
import { getDockerArchiveLayers } from "../../../lib/extractor";
import { ExtractAction } from "../../../lib/extractor/types";
import { streamToBuffer, streamToString } from "../../../lib/stream-utils";

test("image extractor: callbacks are issued when files are found", async (t) => {
  t.plan(2);

  const extractActions: ExtractAction[] = [
    {
      actionName: "read_as_string",
      fileNamePattern: "/snyk/mock.txt",
      callback: async (stream) => {
        const content = await streamToString(stream);
        t.same(content, "Hello, world!", "content read is as expected");
        return Buffer.from([]);
      },
    },
  ];

  // Try a docker-archive first
  await getDockerArchiveLayers(
    "../../fixtures/docker-archives/docker-save/nginx.tar",
    extractActions,
  );

  // Try a skopeo docker-archive
  await getDockerArchiveLayers(
    "../../fixtures/docker-archives/skopeo-copy/nginx.tar",
    extractActions,
  );
});

test("image extractor: can read content with multiple callbacks", async (t) => {
  t.plan(4);

  const extractActions: ExtractAction[] = [
    {
      actionName: "read_as_string",
      fileNamePattern: "/snyk/mock.txt",
      callback: async (stream) => {
        const content = await streamToString(stream);
        t.same(content, "Hello, world!", "content read is as expected");
        return Buffer.from([]);
      },
    },
    {
      actionName: "read_as_buffer",
      fileNamePattern: "/snyk/mock.txt",
      callback: async (stream) => {
        const content = await streamToBuffer(stream);
        t.deepEqual(
          content,
          Buffer.from("Hello, world!", "utf-8"),
          "content read is as expected",
        );
        return Buffer.from([]);
      },
    },
  ];

  // Try a docker-archive first
  await getDockerArchiveLayers(
    "../../fixtures/docker-archives/docker-save/nginx.tar",
    extractActions,
  );

  // Try a skopeo docker-archive
  await getDockerArchiveLayers(
    "../../fixtures/docker-archives/skopeo-copy/nginx.tar",
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
      fileNamePattern,
      callback: async () => returnedContent,
    },
  ];

  const dockerResult = await getDockerArchiveLayers(
    "../../fixtures/docker-archives/skopeo-copy/nginx.tar",
    extractActions,
  );

  const skopeoResult = await getDockerArchiveLayers(
    "../../fixtures/docker-archives/skopeo-copy/nginx.tar",
    extractActions,
  );

  t.deepEqual(
    dockerResult,
    skopeoResult,
    "Docker and Skopeo docker-archive outputs resolve the same way",
  );

  t.ok(
    fileNamePattern in dockerResult &&
      actionName in dockerResult[fileNamePattern] &&
      dockerResult[fileNamePattern][actionName] === returnedContent,
    "The result from extractFromTar is as expected",
  );
});
