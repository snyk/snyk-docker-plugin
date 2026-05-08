import * as fs from "fs";
import { getErrorMessage } from "../error-utils";

const REMOTE_URL_PATTERN = /^https?:\/\//i;
const FETCH_TIMEOUT_MS = 30_000;

/**
 * Loads a VEX document from a local file path or a remote HTTP(S) URL.
 *
 * @param source - Local file path or http(s) URL to a VEX JSON document.
 * @returns The parsed JSON and the resolved source string.
 * @throws Error on any failure (not found, network error, invalid JSON).
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
      throw new Error(`VEX fetch failed: ${response.status} ${response.statusText}`);
    }
    const text = await response.text();
    const raw = JSON.parse(text);
    return { raw, source: url };
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`VEX fetch timed out after ${FETCH_TIMEOUT_MS}ms: ${url}`);
    }
    throw new Error(`Failed to load remote VEX document from '${url}': ${getErrorMessage(err)}`);
  } finally {
    clearTimeout(timer);
  }
}

async function loadLocalVexDocument(
  filePath: string,
): Promise<{ raw: unknown; source: string }> {
  let text: string;
  try {
    text = await fs.promises.readFile(filePath, "utf8");
  } catch (err) {
    throw new Error(`Failed to read VEX file '${filePath}': ${getErrorMessage(err)}`);
  }
  try {
    const raw = JSON.parse(text);
    return { raw, source: filePath };
  } catch (err) {
    throw new Error(`Failed to parse VEX file '${filePath}' as JSON: ${getErrorMessage(err)}`);
  }
}
