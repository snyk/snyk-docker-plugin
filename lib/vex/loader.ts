import * as fs from "fs";
import { getErrorMessage } from "../error-utils";

const REMOTE_URL_PATTERN = /^https?:\/\//i;
const FETCH_TIMEOUT_MS = 30_000;
// Hard cap on the raw VEX document size (bytes). Bounds memory used by
// JSON.parse before the parser-level statement caps can kick in.
export const MAX_VEX_BYTES = 64 * 1024 * 1024; // 64 MiB

/**
 * Loads a VEX document from a local file path or a remote HTTP(S) URL.
 *
 * @param source - Local file path or http(s) URL to a VEX JSON document.
 * @returns The parsed JSON and the resolved source string.
 * @throws Error on any failure (not found, network error, oversize, invalid JSON).
 */
export async function loadVexDocument(
  source: string,
): Promise<{ raw: unknown; source: string }> {
  if (REMOTE_URL_PATTERN.test(source)) {
    return loadRemoteVexDocument(source);
  }
  return loadLocalVexDocument(source);
}

async function loadRemoteVexDocument(
  url: string,
): Promise<{ raw: unknown; source: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(
        `VEX fetch failed: ${response.status} ${response.statusText}`,
      );
    }

    // Reject up-front if the server advertises an oversized payload.
    const contentLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(contentLength) && contentLength > MAX_VEX_BYTES) {
      throw new Error(
        `VEX document at '${url}' exceeds maximum size of ${MAX_VEX_BYTES} bytes (Content-Length: ${contentLength})`,
      );
    }

    const text = await readBodyWithLimit(response, MAX_VEX_BYTES, url);
    const raw = JSON.parse(text);
    return { raw, source: url };
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(
        `VEX fetch timed out after ${FETCH_TIMEOUT_MS}ms: ${url}`,
      );
    }
    throw new Error(
      `Failed to load remote VEX document from '${url}': ${getErrorMessage(
        err,
      )}`,
    );
  } finally {
    clearTimeout(timer);
  }
}

async function readBodyWithLimit(
  response: Response,
  maxBytes: number,
  url: string,
): Promise<string> {
  // Servers can lie about (or omit) Content-Length, so enforce the cap while
  // streaming. Aborts as soon as the threshold is exceeded rather than letting
  // the full body land in memory.
  if (!response.body) {
    return response.text();
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let received = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      received += value.byteLength;
      if (received > maxBytes) {
        throw new Error(
          `VEX document at '${url}' exceeds maximum size of ${maxBytes} bytes`,
        );
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    try {
      await reader.cancel();
    } catch {
      // ignore; reader may already be closed
    }
  }
}

async function loadLocalVexDocument(
  filePath: string,
): Promise<{ raw: unknown; source: string }> {
  // Stat first so we can refuse oversized files without ever opening them.
  // Falls through to readFile's error handling on stat failure.
  try {
    const stat = await fs.promises.stat(filePath);
    if (stat.isFile() && stat.size > MAX_VEX_BYTES) {
      throw new Error(
        `VEX file '${filePath}' exceeds maximum size of ${MAX_VEX_BYTES} bytes (size: ${stat.size})`,
      );
    }
  } catch (err) {
    // Re-throw size-cap errors verbatim; defer other stat errors to readFile,
    // which produces a more familiar "ENOENT" / permission message.
    if (err instanceof Error && err.message.startsWith("VEX file ")) {
      throw err;
    }
  }

  let text: string;
  try {
    text = await fs.promises.readFile(filePath, "utf8");
  } catch (err) {
    throw new Error(
      `Failed to read VEX file '${filePath}': ${getErrorMessage(err)}`,
    );
  }
  try {
    const raw = JSON.parse(text);
    return { raw, source: filePath };
  } catch (err) {
    throw new Error(
      `Failed to parse VEX file '${filePath}' as JSON: ${getErrorMessage(err)}`,
    );
  }
}
