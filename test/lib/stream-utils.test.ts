#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { createReadStream } from "fs";
import { readFileSync } from "fs";
import { join } from "path";
import { test } from "tap";
import {
  streamToBuffer,
  streamToHashSHA1,
  streamToHashSHA256,
  streamToString,
} from "../../lib/stream-utils";

const getFixture = (fixturePath) =>
  join(__dirname, "../fixtures/generic", fixturePath);

test("stream-utils.streamToString()", async (t) => {
  const fixture = getFixture("small-sample-text.txt");
  const fileStream = createReadStream(fixture);

  const fileContent = await streamToString(fileStream);
  const expectedContent = readFileSync(fixture, { encoding: "utf-8" });

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

test("stream-utils.streamToHashSHA1()", async (t) => {
  const fixture = getFixture("small-sample-text.txt");
  const fileStream = createReadStream(fixture);

  const hashOfFile = await streamToHashSHA1(fileStream);

  t.deepEqual(
    hashOfFile,
    "943a702d06f34599aee1f8da8ef9f7296031d699",
    "streamToHashSHA1 returns the expected hash",
  );
});

test("stream-utils.streamToHashSHA256()", async (t) => {
  const fixture = getFixture("small-sample-text.txt");
  const fileStream = createReadStream(fixture);

  const hashOfFile = await streamToHashSHA256(fileStream);

  t.deepEqual(
    hashOfFile,
    "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3",
    "streamToHashSHA256 returns the expected hash",
  );
});
