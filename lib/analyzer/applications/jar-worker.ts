import { parentPort } from "worker_threads";
import { jarFilesToScannedResults } from "./java";
import { FilePathToBuffer } from "./types";

parentPort!.on(
  "message",
  async (msg: {
    filePathToBuffer: FilePathToBuffer;
    targetImage: string;
    desiredLevelsOfUnpacking: number;
  }) => {
    try {
      const results = await jarFilesToScannedResults(
        msg.filePathToBuffer,
        msg.targetImage,
        msg.desiredLevelsOfUnpacking,
      );

      const serializable = results.map((r) => ({
        facts: r.facts.map((f) => ({
          type: f.type,
          data: (f as any).data,
        })),
        identity: r.identity,
      }));

      parentPort!.postMessage({ results: serializable });
    } catch (err) {
      parentPort!.postMessage({
        error: err instanceof Error ? err.message : String(err),
      });
    }
  },
);
