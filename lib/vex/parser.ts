import { VexStatement, VexStatus } from "../facts";

type ParsedVexDocument = {
  format: "openvex" | "cyclonedx-vex";
  statements: VexStatement[];
};

/**
 * Parses a raw VEX document (OpenVEX or CycloneDX-VEX format) into normalized statements.
 *
 * @param raw - The raw parsed JSON object.
 * @returns Normalized format and statements list.
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

  for (const s of rawStatements) {
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

    const vulnerabilityIds = resolveOpenVexVulnerabilityIds(stmt.vulnerability);
    const productIds = resolveOpenVexProductIds(stmt.products);

    for (const vulnerabilityId of vulnerabilityIds) {
      for (const productId of productIds) {
        if (!vulnerabilityId || !productId) {
          continue;
        }
        statements.push({ vulnerabilityId, productId, status, justification });
      }
    }
  }

  return { format: "openvex", statements };
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
  for (const product of products) {
    if (typeof product === "string") {
      ids.push(product);
    } else if (typeof product === "object" && product !== null) {
      const p = product as Record<string, unknown>;
      const id = (p["@id"] ?? p.id) as string | undefined;
      if (id) {
        ids.push(id);
      }
      // Also process subcomponents if present
      if (Array.isArray(p.subcomponents)) {
        for (const sub of p.subcomponents) {
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
    }
  }
  return ids;
}

// ─── CycloneDX-VEX ───────────────────────────────────────────────────────────

function parseCycloneDxVex(doc: Record<string, unknown>): ParsedVexDocument {
  const vulnerabilities = doc.vulnerabilities as unknown[];
  const statements: VexStatement[] = [];

  for (const v of vulnerabilities) {
    if (typeof v !== "object" || v === null) {
      continue;
    }
    const vuln = v as Record<string, unknown>;
    const vulnerabilityId = vuln.id as string | undefined;
    if (!vulnerabilityId) {
      continue;
    }

    const affects = Array.isArray(vuln.affects) ? vuln.affects : [];
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
      statements.push({
        vulnerabilityId,
        productId,
        status,
        ...(justification ? { justification } : {}),
      });
    }
  }

  return { format: "cyclonedx-vex", statements };
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
