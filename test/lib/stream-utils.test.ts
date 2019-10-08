import { createReadStream } from "fs";
import { test } from "tap";
import { streamToBuffer, streamToString } from "../../lib/stream-utils";

test("stream-utils.streamToString()", async (t) => {
  const fileStream = createReadStream(
    "../fixtures/generic/small-sample-text.txt",
  );
  const fileContent = await streamToString(fileStream);
  t.same(fileContent, "Hello, world!");
});

test("stream-utils.streamToBuffer()", async (t) => {
  const fileStream = createReadStream(
    "../fixtures/generic/small-sample-text.txt",
  );
  const fileContent = await streamToBuffer(fileStream);
  t.deepEqual(
    fileContent,
    Buffer.from("Hello, world!"),
    "streamToBuffer returns the expected content",
  );
});
