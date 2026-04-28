import * as path from "path";
import { Worker } from "worker_threads";
import { AppDepsScanResultWithoutTarget, FilePathToBuffer } from "./types";

interface JarWorkerMessage {
  filePathToBuffer: FilePathToBuffer;
  targetImage: string;
  desiredLevelsOfUnpacking: number;
}

interface WorkerResponse {
  results?: AppDepsScanResultWithoutTarget[];
  error?: string;
}

export function runJarAnalysisInWorker(
  filePathToBuffer: FilePathToBuffer,
  targetImage: string,
  desiredLevelsOfUnpacking: number,
): Promise<AppDepsScanResultWithoutTarget[]> {
  return new Promise((resolve, reject) => {
    const workerPath = path.resolve(__dirname, "jar-worker.js");
    const worker = new Worker(workerPath);

    const message: JarWorkerMessage = {
      filePathToBuffer,
      targetImage,
      desiredLevelsOfUnpacking,
    };

    let settled = false;

    worker.on("message", (response: WorkerResponse) => {
      if (settled) {
        return;
      }
      settled = true;
      worker.terminate();
      if (response.error) {
        reject(new Error(response.error));
      } else {
        resolve(response.results || []);
      }
    });

    worker.on("error", (err) => {
      if (settled) {
        return;
      }
      settled = true;
      worker.terminate();
      reject(err);
    });

    worker.on("exit", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      if (code !== 0) {
        reject(new Error(`JAR worker exited with code ${code}`));
      }
    });

    // Use structured clone (no transfer list) to avoid invalidating
    // buffers that may still be referenced in extractedLayers.
    worker.postMessage(message);
  });
}
