import { VexStatement, VexStatus } from "../facts";

export interface ParsedVexDocument {
  format: "openvex" | "cyclonedx-vex";
  statements: VexStatement[];
  warnings: string[];
}

// Hard limits to bound memory and CPU on adversarial or accidentally huge VEX
// documents. The OpenVEX path multiplies vulnerabilityIds × productIds per
// statement, so we cap each axis as well as the final output.
export const VEX_LIMITS = {
  // Max raw entries we will iterate from the document.
  maxStatements: 10_000,
  // Per-statement caps for the cartesian product expansion.
  maxProductsPerStatement: 1_000,
  maxSubcomponentsPerProduct: 1_000,
  maxVulnerabilityIdsPerStatement: 1_000,
  // Total normalized statements we will emit.
  maxEmittedStatements: 100_000,
};

/**
 * Parses a raw VEX document (OpenVEX or CycloneDX-VEX format) into normalized statements.
 *
 * @param raw - The raw parsed JSON object.
 * @returns Normalized format, statements list, and any non-fatal warnings.
 * @throws Error if the document format is not recognized.
 */
export function parseVexDocument(raw: unknown): ParsedVexDocument {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Unrecognized VEX document format");
  }

  const doc = raw as Record<string, unknown>;

  if (isCycloneDxVex(doc)) {
    return parseCycloneDxVex(doc);
  }

  if (isOpenVex(doc)) {
    return parseOpenVex(doc);
  }

  throw new Error("Unrecognized VEX document format");
}

function isCycloneDxVex(doc: Record<string, unknown>): boolean {
  return doc.bomFormat === "CycloneDX" && Array.isArray(doc.vulnerabilities);
}

function isOpenVex(doc: Record<string, unknown>): boolean {
  const context = doc["@context"];
  const hasContext =
    (typeof context === "string" && context.includes("openvex")) ||
    doc["@id"] !== undefined;
  return hasContext && Array.isArray(doc.statements);
}

// ─── OpenVEX ─────────────────────────────────────────────────────────────────

function parseOpenVex(doc: Record<string, unknown>): ParsedVexDocument {
  const rawStatements = doc.statements as unknown[];
  const statements: VexStatement[] = [];
  const warnings: string[] = [];

  const { sliced: limitedStatements, truncated: statementsTruncated } =
    sliceWithFlag(rawStatements, VEX_LIMITS.maxStatements);
  if (statementsTruncated) {
    warnings.push(
      `VEX document statements truncated to first ${VEX_LIMITS.maxStatements} entries`,
    );
  }

  let emittedCapHit = false;
  outer: for (const s of limitedStatements) {
    if (typeof s !== "object" || s === null) {
      continue;
    }
    const stmt = s as Record<string, unknown>;
    const status = stmt.status as VexStatus | undefined;
    if (!status) {
      continue;
    }
    const justification =
      typeof stmt.justification === "string" ? stmt.justification : undefined;

    const vulnerabilityIds = capArray(
      resolveOpenVexVulnerabilityIds(stmt.vulnerability),
      VEX_LIMITS.maxVulnerabilityIdsPerStatement,
    );
    const productIds = capArray(
      resolveOpenVexProductIds(stmt.products),
      VEX_LIMITS.maxProductsPerStatement,
    );

    for (const vulnerabilityId of vulnerabilityIds) {
      for (const productId of productIds) {
        if (!vulnerabilityId || !productId) {
          continue;
        }
        if (statements.length >= VEX_LIMITS.maxEmittedStatements) {
          emittedCapHit = true;
          break outer;
        }
        statements.push({ vulnerabilityId, productId, status, justification });
      }
    }
  }

  if (emittedCapHit) {
    warnings.push(
      `VEX document produced more than ${VEX_LIMITS.maxEmittedStatements} statements; remainder discarded`,
    );
  }

  return { format: "openvex", statements, warnings };
}

function resolveOpenVexVulnerabilityIds(vulnerability: unknown): string[] {
  if (typeof vulnerability === "string") {
    return [vulnerability];
  }
  if (typeof vulnerability === "object" && vulnerability !== null) {
    const v = vulnerability as Record<string, unknown>;
    const id = (v.name ?? v["@id"]) as string | undefined;
    return id ? [id] : [];
  }
  return [];
}

function resolveOpenVexProductIds(products: unknown): string[] {
  if (!Array.isArray(products)) {
    return [];
  }
  const ids: string[] = [];
  const productCap = VEX_LIMITS.maxProductsPerStatement;
  // Walk products until we hit the cap; subcomponents are charged against the
  // same budget so that a single product with millions of subcomponents cannot
  // explode the array.
  for (let i = 0; i < products.length && ids.length < productCap; i++) {
    const product = products[i];
    if (typeof product === "string") {
      ids.push(product);
      continue;
    }
    if (typeof product !== "object" || product === null) {
      continue;
    }
    const p = product as Record<string, unknown>;
    const id = (p["@id"] ?? p.id) as string | undefined;
    if (id) {
      ids.push(id);
    }
    if (!Array.isArray(p.subcomponents)) {
      continue;
    }
    const subCap = Math.min(
      VEX_LIMITS.maxSubcomponentsPerProduct,
      productCap - ids.length,
    );
    for (let j = 0; j < p.subcomponents.length && j < subCap; j++) {
      const sub = p.subcomponents[j];
      if (typeof sub === "string") {
        ids.push(sub);
      } else if (typeof sub === "object" && sub !== null) {
        const s = sub as Record<string, unknown>;
        const subId = (s["@id"] ?? s.id) as string | undefined;
        if (subId) {
          ids.push(subId);
        }
      }
    }
  }
  return ids;
}

// ─── CycloneDX-VEX ───────────────────────────────────────────────────────────

function parseCycloneDxVex(doc: Record<string, unknown>): ParsedVexDocument {
  const rawVulnerabilities = doc.vulnerabilities as unknown[];
  const statements: VexStatement[] = [];
  const warnings: string[] = [];

  const { sliced: limitedVulnerabilities, truncated: vulnsTruncated } =
    sliceWithFlag(rawVulnerabilities, VEX_LIMITS.maxStatements);
  if (vulnsTruncated) {
    warnings.push(
      `VEX document vulnerabilities truncated to first ${VEX_LIMITS.maxStatements} entries`,
    );
  }

  let emittedCapHit = false;
  outer: for (const v of limitedVulnerabilities) {
    if (typeof v !== "object" || v === null) {
      continue;
    }
    const vuln = v as Record<string, unknown>;
    const vulnerabilityId = vuln.id as string | undefined;
    if (!vulnerabilityId) {
      continue;
    }

    const affectsRaw = Array.isArray(vuln.affects) ? vuln.affects : [];
    const affects = capArray(affectsRaw, VEX_LIMITS.maxProductsPerStatement);
    const analysis =
      typeof vuln.analysis === "object" && vuln.analysis !== null
        ? (vuln.analysis as Record<string, unknown>)
        : {};

    const status = mapCycloneDxState(analysis.state as string | undefined);
    const justification =
      (analysis.justification as string | undefined) ??
      (analysis.detail as string | undefined);

    for (const affect of affects) {
      if (typeof affect !== "object" || affect === null) {
        continue;
      }
      const a = affect as Record<string, unknown>;
      const productId = a.ref as string | undefined;
      if (!productId) {
        continue;
      }
      if (statements.length >= VEX_LIMITS.maxEmittedStatements) {
        emittedCapHit = true;
        break outer;
      }
      statements.push({
        vulnerabilityId,
        productId,
        status,
        ...(justification ? { justification } : {}),
      });
    }
  }

  if (emittedCapHit) {
    warnings.push(
      `VEX document produced more than ${VEX_LIMITS.maxEmittedStatements} statements; remainder discarded`,
    );
  }

  return { format: "cyclonedx-vex", statements, warnings };
}

function mapCycloneDxState(state: string | undefined): VexStatus {
  switch (state) {
    case "exploitable":
      return "affected";
    case "resolved":
    case "resolved_with_pedigree":
      return "fixed";
    case "in_triage":
      return "under_investigation";
    case "false_positive":
    case "not_affected":
      return "not_affected";
    default:
      return "under_investigation";
  }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

function sliceWithFlag<T>(
  arr: T[],
  limit: number,
): { sliced: T[]; truncated: boolean } {
  if (arr.length <= limit) {
    return { sliced: arr, truncated: false };
  }
  return { sliced: arr.slice(0, limit), truncated: true };
}

function capArray<T>(arr: T[], limit: number): T[] {
  return arr.length <= limit ? arr : arr.slice(0, limit);
}
