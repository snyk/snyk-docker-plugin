import { PassThrough, Readable } from "stream";
import { applyCallbacks } from "../../../lib/extractor/callbacks";
import {
  ExtractAction,
  FileNameAndContent,
} from "../../../lib/extractor/types";
import { streamToString } from "../../../lib/stream-utils";

const MEGABYTE = 1024 * 1024;
const CHUNK_SIZE = 64 * 1024;

function createMultiMegabyteStream(sizeMb: number): Readable {
  const totalBytes = sizeMb * MEGABYTE;
  let sent = 0;

  return new Readable({
    read() {
      if (sent >= totalBytes) {
        this.push(null);
        return;
      }
      const remaining = totalBytes - sent;
      const size = Math.min(CHUNK_SIZE, remaining);
      this.push(Buffer.alloc(size, 0x42));
      sent += size;
    },
  });
}

async function baselineApplyCallbacks(
  matchedActions: ExtractAction[],
  fileContentStream: Readable,
  streamSize?: number,
): Promise<FileNameAndContent> {
  const result: FileNameAndContent = {};
  const actionsToAwait = matchedActions.map((action) => {
    // Using a pass through allows us to read the stream multiple times.
    const streamCopy = new PassThrough();
    fileContentStream.pipe(streamCopy);

    // Queue the promise but don't await on it yet: we want consumers to start around the same time.
    const promise =
      action.callback !== undefined
        ? action.callback(streamCopy, streamSize)
        : // If no callback was provided for this action then return as string by default.
          streamToString(streamCopy);

    return promise.then((content) => {
      // Assign the result once the Promise is complete.
      if (content) {
        result[action.actionName] = content;
      }
    });
  });

  await Promise.all(actionsToAwait);

  return result;
}

function bufferAction(
  actionName: string,
  callback?: ExtractAction["callback"],
): ExtractAction {
  return {
    actionName,
    filePathMatches: () => true,
    callback:
      callback ??
      (async (stream) => {
        const chunks: Buffer[] = [];
        for await (const chunk of stream) {
          chunks.push(Buffer.from(chunk));
        }
        return Buffer.concat(chunks);
      }),
  };
}

describe("applyCallbacks stream passthrough bypass", () => {
  const streamSizeMb = 4;

  it("matches baseline for a single matched action", async () => {
    const action = bufferAction("content");

    const optimizedStream = createMultiMegabyteStream(streamSizeMb);
    const baselineStream = createMultiMegabyteStream(streamSizeMb);

    const optimized = await applyCallbacks(
      [action],
      optimizedStream,
      streamSizeMb,
    );
    const baseline = await baselineApplyCallbacks(
      [action],
      baselineStream,
      streamSizeMb,
    );

    expect(optimized).toEqual(baseline);
  });

  it("matches baseline for two matched actions over the same stream size", async () => {
    const actions = [
      bufferAction("first"),
      bufferAction("second", async (stream) => {
        const text = await streamToString(stream);
        return text.length.toString();
      }),
    ];

    const optimizedStream = createMultiMegabyteStream(streamSizeMb);
    const baselineStream = createMultiMegabyteStream(streamSizeMb);

    const optimized = await applyCallbacks(
      actions,
      optimizedStream,
      streamSizeMb,
    );
    const baseline = await baselineApplyCallbacks(
      actions,
      baselineStream,
      streamSizeMb,
    );

    expect(optimized).toEqual(baseline);
  });

  it("omits the result key when a callback resolves undefined", async () => {
    const action: ExtractAction = {
      actionName: "empty",
      filePathMatches: () => true,
      callback: async () => undefined,
    };

    const optimizedStream = createMultiMegabyteStream(1);
    const baselineStream = createMultiMegabyteStream(1);

    const optimized = await applyCallbacks([action], optimizedStream);
    const baseline = await baselineApplyCallbacks([action], baselineStream);

    expect(optimized).toEqual({});
    expect(baseline).toEqual({});
    expect(Object.prototype.hasOwnProperty.call(optimized, "empty")).toBe(
      false,
    );
  });

  it("rejects with the same error as baseline when a callback rejects", async () => {
    const expectedError = new Error("callback failed");
    const action: ExtractAction = {
      actionName: "failing",
      filePathMatches: () => true,
      callback: async () => {
        throw expectedError;
      },
    };

    const optimizedStream = createMultiMegabyteStream(1);
    const baselineStream = createMultiMegabyteStream(1);

    await expect(applyCallbacks([action], optimizedStream)).rejects.toBe(
      expectedError,
    );
    await expect(baselineApplyCallbacks([action], baselineStream)).rejects.toBe(
      expectedError,
    );
  });

  it("leaves the source stream drainable via resume when callback resolves on first chunk", async () => {
    const totalBytes = 2 * MEGABYTE;
    let produced = 0;
    let drained = 0;
    let firstChunkSize = 0;

    const stream = new Readable({
      read() {
        if (produced >= totalBytes) {
          this.push(null);
          return;
        }
        const size = Math.min(CHUNK_SIZE, totalBytes - produced);
        this.push(Buffer.alloc(size, 0x42));
        produced += size;
      },
    });
    stream.pause();

    const action: ExtractAction = {
      actionName: "early",
      filePathMatches: () => true,
      callback: (dataStream) =>
        new Promise((resolve) => {
          dataStream.once("data", (chunk: Buffer) => {
            firstChunkSize = chunk.length;
            dataStream.pause();
            resolve("partial");
          });
          dataStream.resume();
        }),
    };

    const result = await applyCallbacks([action], stream);
    expect(result).toEqual({ early: "partial" });

    await new Promise<void>((resolve, reject) => {
      stream.on("data", (chunk: Buffer) => {
        drained += chunk.length;
      });
      stream.on("end", resolve);
      stream.on("error", reject);
      stream.resume();
    });

    expect(firstChunkSize + drained).toBe(totalBytes);
  });

  it("is faster than baseline for the single-action path", async () => {
    const action = bufferAction("content");
    const benchmarkSizeMb = 8;
    const runs = 5;

    const measure = async (
      fn: (
        actions: ExtractAction[],
        stream: Readable,
        streamSize?: number,
      ) => Promise<FileNameAndContent>,
    ): Promise<number> => {
      const times: number[] = [];
      for (let i = 0; i < runs; i++) {
        const stream = createMultiMegabyteStream(benchmarkSizeMb);
        const start = process.hrtime.bigint();
        await fn([action], stream, benchmarkSizeMb);
        times.push(Number(process.hrtime.bigint() - start) / 1e6);
      }
      return Math.min(...times);
    };

    // Warmup
    await measure(baselineApplyCallbacks);

    const baselineMs = await measure(baselineApplyCallbacks);
    const optimizedMs = await measure(applyCallbacks);

     
    console.log(
      `applyCallbacks single-action: optimized=${optimizedMs.toFixed(
        2,
      )}ms baseline=${baselineMs.toFixed(2)}ms`,
    );

    expect(optimizedMs).toBeLessThan(baselineMs);
  });
});
