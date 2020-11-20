import { createReadStream } from "fs";
import { readFileSync } from "fs";
import { join } from "path";
import { test } from "tap";
import { streamToBuffer, streamToString } from "../../lib/stream-utils";

const getFixture = (fixturePath) =>
  join(__dirname, "../fixtures/generic", fixturePath);

test("stream-utils.streamToString()", async (t) => {
  const fixture = getFixture("small-sample-text.txt");
  const fileStream = createReadStream(fixture);

  const fileContent = await streamToString(fileStream);
  const expectedContent = readFileSync(fixture, { encoding: "utf-8" });

  t.same(fileContent, expectedContent, "Returned the expected string");
});

test("stream-utils.streamToString(base64)", async (t) => {
  const fixture = getFixture("small-sample-text.txt");
  const fileStream = createReadStream(fixture);

  const fileContent = await streamToString(fileStream, undefined, "base64");
  const expectedContent = readFileSync(fixture, { encoding: "base64" });

  t.same(fileContent, expectedContent, "Returned the expected string");
});

test("stream-utils.streamToBuffer()", async (t) => {
  const fixture = getFixture("small-sample-text.txt");
  const fileStream = createReadStream(fixture);

  const fileContent = await streamToBuffer(fileStream);
  const expectedContent = readFileSync(fixture);

  t.deepEqual(
    fileContent,
    expectedContent,
    "streamToBuffer returns the expected content",
  );
});
