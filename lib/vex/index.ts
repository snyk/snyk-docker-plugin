import { VexStatementsFact, PluginWarningsFact } from "../facts";
import { PluginResponse } from "../types";
import { getErrorMessage } from "../error-utils";
import { loadVexDocument } from "./loader";
import { parseVexDocument } from "./parser";

export { loadVexDocument } from "./loader";
export { parseVexDocument } from "./parser";

/**
 * Loads and parses a VEX document, returning a typed VexStatementsFact.
 */
export async function buildVexFact(
  vexFilePath: string,
): Promise<VexStatementsFact> {
  const { raw, source } = await loadVexDocument(vexFilePath);
  const { format, statements } = parseVexDocument(raw);
  return {
    type: "vexStatements",
    data: { source, format, statements },
  };
}

/**
 * Post-processes a PluginResponse by attaching VEX statements as a fact to every
 * ScanResult. If loading or parsing fails the response is returned unchanged and
 * a human-readable warning is returned instead of throwing.
 */
export async function attachVexFactsToScanResults(
  response: PluginResponse,
  vexFilePath: string | undefined,
): Promise<{ response: PluginResponse; warning?: string }> {
  if (!vexFilePath) {
    return { response };
  }

  let vexFact: VexStatementsFact;
  try {
    vexFact = await buildVexFact(vexFilePath);
  } catch (err) {
    const warning = `Failed to load VEX file '${vexFilePath}': ${getErrorMessage(err)}`;
    return { response, warning };
  }

  const updatedScanResults = response.scanResults.map((result) => ({
    ...result,
    facts: [...result.facts, vexFact],
  }));

  return {
    response: {
      ...response,
      scanResults: updatedScanResults,
    },
  };
}

/**
 * Surfaces a VEX warning on the first ScanResult's pluginWarnings fact.
 * Creates the pluginWarnings fact if it does not yet exist.
 */
export function appendVexWarningToScanResult(
  response: PluginResponse,
  warning: string,
): PluginResponse {
  const scanResults = [...response.scanResults];
  const first = scanResults[0];
  if (!first) {
    return response;
  }

  const existingFact = first.facts.find(
    (f) => f.type === "pluginWarnings",
  ) as PluginWarningsFact | undefined;

  if (existingFact) {
    existingFact.data.parameterChecks = [
      ...(existingFact.data.parameterChecks ?? []),
      warning,
    ];
  } else {
    first.facts = [
      ...first.facts,
      {
        type: "pluginWarnings",
        data: { parameterChecks: [warning] },
      } as PluginWarningsFact,
    ];
  }

  scanResults[0] = { ...first };
  return { ...response, scanResults };
}
