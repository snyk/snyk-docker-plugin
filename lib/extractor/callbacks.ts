import { PassThrough, Readable } from "stream";
import { streamToBuffer } from "../stream-utils";
import { ExtractAction, FileContent, FileNameAndContent } from "./types";

interface ICallbackToAwait {
  extractActionName: string;
  promise: Promise<FileContent>;
}

export async function applyCallbacks(
  matchedActions: ExtractAction[],
  fileContentStream: Readable,
): Promise<FileNameAndContent> {
  const result: FileNameAndContent = {};

  const callbacksToAwait: ICallbackToAwait[] = matchedActions.map((action) => {
    // Using a pass through allows us to read a stream with multiple consumers.
    const streamCopy = new PassThrough();
    fileContentStream.pipe(streamCopy);

    // Queue the promise but don't await on it yet: we want consumers to start around the same time.
    const promise =
      action.callback !== undefined
        ? action.callback(streamCopy)
        : streamToBuffer(streamCopy); // Return just the file contents as a Buffer by default.

    return {
      extractActionName: action.actionName,
      promise,
    };
  });

  callbacksToAwait.forEach(async (callback) => {
    result[callback.extractActionName] = await callback.promise;
  });

  return result;
}
