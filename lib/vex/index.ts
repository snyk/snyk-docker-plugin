import { getErrorMessage } from "../error-utils";
import { PluginWarningsFact, VexStatementsFact } from "../facts";
import { PluginResponse } from "../types";
import { loadVexDocument } from "./loader";
import { parseVexDocument } from "./parser";

export { loadVexDocument } from "./loader";
export { parseVexDocument, VEX_LIMITS } from "./parser";

interface BuiltVexFact {
  fact: VexStatementsFact;
  warnings: string[];
}

/**
 * Loads and parses a VEX document, returning a typed VexStatementsFact and any
 * non-fatal warnings produced while parsing (e.g. truncation of large input).
 */
export async function buildVexFact(vexFilePath: string): Promise<BuiltVexFact> {
  const { raw, source } = await loadVexDocument(vexFilePath);
  const { format, statements, warnings } = parseVexDocument(raw);
  return {
    fact: {
      type: "vexStatements",
      data: { source, format, statements },
    },
    warnings,
  };
}

/**
 * Post-processes a PluginResponse by attaching VEX statements as a fact to every
 * ScanResult. If loading or parsing fails the response is returned unchanged and
 * a human-readable warning is returned instead of throwing. Non-fatal parser
 * warnings (e.g. truncation) are returned alongside the populated response.
 */
export async function attachVexFactsToScanResults(
  response: PluginResponse,
  vexFilePath: string | undefined,
): Promise<{ response: PluginResponse; warnings: string[] }> {
  if (!vexFilePath) {
    return { response, warnings: [] };
  }

  let built: BuiltVexFact;
  try {
    built = await buildVexFact(vexFilePath);
  } catch (err) {
    const warning = `Failed to load VEX file '${vexFilePath}': ${getErrorMessage(
      err,
    )}`;
    return { response, warnings: [warning] };
  }

  const updatedScanResults = response.scanResults.map((result) => ({
    ...result,
    facts: [...result.facts, built.fact],
  }));

  return {
    response: {
      ...response,
      scanResults: updatedScanResults,
    },
    warnings: built.warnings,
  };
}

/**
 * Surfaces VEX warnings on the first ScanResult's pluginWarnings fact.
 * Creates the pluginWarnings fact if it does not yet exist. No-op when no
 * warnings are supplied.
 */
export function appendVexWarningsToScanResult(
  response: PluginResponse,
  warnings: string[],
): PluginResponse {
  if (warnings.length === 0) {
    return response;
  }
  const scanResults = [...response.scanResults];
  const first = scanResults[0];
  if (!first) {
    return response;
  }

  const existingFact = first.facts.find((f) => f.type === "pluginWarnings") as
    | PluginWarningsFact
    | undefined;

  if (existingFact) {
    existingFact.data.parameterChecks = [
      ...(existingFact.data.parameterChecks ?? []),
      ...warnings,
    ];
  } else {
    first.facts = [
      ...first.facts,
      {
        type: "pluginWarnings",
        data: { parameterChecks: [...warnings] },
      } as PluginWarningsFact,
    ];
  }

  scanResults[0] = { ...first };
  return { ...response, scanResults };
}
