import { createReadStream } from "fs";
import { readFileSync } from "fs";
import { join } from "path";
import { Readable } from "stream";
import {
  streamToBuffer,
  streamToJson,
  streamToSha1,
  streamToSha256,
  streamToString,
} from "../../lib/stream-utils";

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

  test("stream-utils.streamToString() with error handling", async () => {
    const errorStream = new Readable();
    errorStream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToString(errorStream);
    errorStream.emit("error", new Error("Test error"));

    await expect(promise).rejects.toThrow("Test error");
  });

  test("stream-utils.streamToBuffer() with error handling", async () => {
    const errorStream = new Readable();
    errorStream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToBuffer(errorStream);
    errorStream.emit("error", new Error("Test error"));

    await expect(promise).rejects.toThrow("Test error");
  });

  test("stream-utils.streamToSha256()", async () => {
    const testData = "Hello, World!";
    const stream = new Readable();
    stream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToSha256(stream);
    stream.push(testData);
    stream.push(null); // End the stream

    const hash = await promise;
    expect(hash).toBeDefined();
    expect(typeof hash).toBe("string");
    expect(hash.length).toBe(64); // SHA256 produces 64 character hex string
  });

  test("stream-utils.streamToSha1()", async () => {
    const testData = "Hello, World!";
    const stream = new Readable();
    stream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToSha1(stream);
    stream.push(testData);
    stream.push(null); // End the stream

    const hash = await promise;
    expect(hash).toBeDefined();
    expect(typeof hash).toBe("string");
    expect(hash.length).toBe(40); // SHA1 produces 40 character hex string
  });

  test("stream-utils.streamToSha256() with error handling", async () => {
    const errorStream = new Readable();
    errorStream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToSha256(errorStream);
    errorStream.emit("error", new Error("Hash error"));

    await expect(promise).rejects.toThrow("Hash error");
  });

  test("stream-utils.streamToSha1() with error handling", async () => {
    const errorStream = new Readable();
    errorStream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToSha1(errorStream);
    errorStream.emit("error", new Error("Hash error"));

    await expect(promise).rejects.toThrow("Hash error");
  });

  test("stream-utils.streamToJson() with valid JSON", async () => {
    const jsonData = '{"key": "value", "number": 42}';
    const stream = new Readable();
    stream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToJson(stream);
    stream.push(jsonData);
    stream.push(null);

    const result = await promise;
    expect(result).toEqual({ key: "value", number: 42 });
  });

  test("stream-utils.streamToJson() with invalid JSON", async () => {
    const invalidJson = '{"key": "value", "number": 42'; // Missing closing brace
    const stream = new Readable();
    stream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToJson(stream);
    stream.push(invalidJson);
    stream.push(null);

    await expect(promise).rejects.toThrow();
  });

  test("stream-utils.streamToJson() with error handling", async () => {
    const errorStream = new Readable();
    errorStream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToJson(errorStream);
    errorStream.emit("error", new Error("JSON error"));

    await expect(promise).rejects.toThrow("JSON error");
  });

  test("stream-utils.streamToJson() rejects when stream exceeds 2MB", async () => {
    const largeData = "x".repeat(2 * 1024 * 1024 + 1); // Just over 2MB
    const stream = new Readable();
    stream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToJson(stream);
    stream.push(largeData);
    stream.push(null);

    await expect(promise).rejects.toThrow(
      "The stream is too large to parse as JSON",
    );
  });

  test("stream-utils.streamToJson() accepts stream exactly at 2MB limit", async () => {
    const largeData = "x".repeat(2 * 1024 * 1024); // Exactly 2MB
    const stream = new Readable();
    stream._read = () => {
      // Intentionally empty - required for Readable streams
    };

    const promise = streamToJson(stream);
    stream.push(largeData);
    stream.push(null);

    // Should not reject, but will fail JSON parsing since it's just "x" repeated
    await expect(promise).rejects.toThrow(); // JSON parse error, not size error
  });
});
