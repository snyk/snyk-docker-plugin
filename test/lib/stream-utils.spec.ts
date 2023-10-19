import { createReadStream } from "fs";
import { readFileSync } from "fs";
import { join } from "path";
import { streamToBuffer, streamToString } from "../../lib/stream-utils";

describe("stream-utils", () => {
  const getFixture = (fixturePath) =>
    join(__dirname, "../fixtures/generic", fixturePath);

  test("stream-utils.streamToString()", async () => {
    const fixture = getFixture("small-sample-text.txt");
    const fileStream = createReadStream(fixture);

    const fileContent = await streamToString(fileStream);
    const expectedContent = readFileSync(fixture, { encoding: "utf-8" });

    //  returned the expected string
    expect(fileContent).toEqual(expectedContent);
  });

  test("stream-utils.streamToString(base64)", async () => {
    const fixture = getFixture("small-sample-text.txt");
    const fileStream = createReadStream(fixture);

    const fileContent = await streamToString(fileStream, undefined, "base64");
    const expectedContent = readFileSync(fixture, { encoding: "base64" });

    //  returned the expected string
    expect(fileContent).toEqual(expectedContent);
  });

  test("stream-utils.streamToBuffer()", async () => {
    const fixture = getFixture("small-sample-text.txt");
    const fileStream = createReadStream(fixture);

    const fileContent = await streamToBuffer(fileStream);
    const expectedContent = readFileSync(fixture);

    //  streamToBuffer returns the expected content
    expect(fileContent).toEqual(expectedContent);
  });
});
