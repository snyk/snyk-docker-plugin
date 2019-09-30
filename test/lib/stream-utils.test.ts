import { createReadStream } from "fs";
import { test } from "tap";
import { streamToString } from "../../lib/stream-utils";

test("stream-utils.streamToString()", async (t) => {
  const fileStream = createReadStream(
    "../fixtures/generic/small-sample-text.txt",
  );
  const fileContent = await streamToString(fileStream);
  t.same(fileContent, "Hello, world!");
});
