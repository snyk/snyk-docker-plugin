import * as Debug from "debug";

const debug = Debug("snyk-docker-plugin:rust:cargo-lock-parser");

export interface CargoDependencyRef {
  name: string;
  version?: string;
}

export interface CargoPackage {
  name: string;
  version: string;
  source?: string;
  dependencies: CargoDependencyRef[];
}

export interface CargoLock {
  lockfileVersion: number;
  packages: CargoPackage[];
}

interface PartialPackage {
  name?: string;
  version?: string;
  source?: string;
  dependencies: CargoDependencyRef[];
}

const PACKAGE_TABLE = "[[package]]";

function isTableHeader(line: string): boolean {
  return line.startsWith("[") && line.endsWith("]");
}

function parseStringValue(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function looksLikeVersion(token: string): boolean {
  return /^\d/.test(token);
}

function parseDependencyRef(raw: string): CargoDependencyRef {
  const trimmed = raw.trim();
  const tokens = trimmed.split(/\s+/);
  const name = tokens[0];
  let version: string | undefined;

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith("(")) {
      break;
    }
    if (looksLikeVersion(token)) {
      version = token;
      break;
    }
  }

  return version !== undefined ? { name, version } : { name };
}

function extractQuotedStrings(content: string): string[] {
  const results: string[] = [];
  const regex = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    results.push(match[1]);
  }
  return results;
}

function finalizePackage(
  partial: PartialPackage | null,
): CargoPackage | undefined {
  if (partial?.name && partial.version) {
    return {
      name: partial.name,
      version: partial.version,
      ...(partial.source !== undefined ? { source: partial.source } : {}),
      dependencies: partial.dependencies,
    };
  }
  return undefined;
}

export function parseCargoLock(content: string): CargoLock {
  try {
    return parseCargoLockInternal(content);
  } catch (err) {
    debug("failed to parse Cargo.lock: %s", err);
    return { lockfileVersion: 1, packages: [] };
  }
}

function parseCargoLockInternal(content: string): CargoLock {
  const lines = content.split(/\r?\n/);
  let explicitVersion: number | undefined;
  let sawMetadataTable = false;
  let sawFirstPackage = false;
  let inIgnoredTable = false;
  let currentPackage: PartialPackage | null = null;
  const packages: CargoPackage[] = [];

  let pendingDependencies: string[] | null = null;
  let dependenciesBuffer = "";

  const flushCurrentPackage = (): void => {
    const finalized = finalizePackage(currentPackage);
    if (finalized) {
      packages.push(finalized);
    }
    currentPackage = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (line === "" || line.startsWith("#")) {
      continue;
    }

    if (pendingDependencies !== null) {
      dependenciesBuffer += " " + line;
      if (line.includes("]")) {
        const refs =
          extractQuotedStrings(dependenciesBuffer).map(parseDependencyRef);
        if (currentPackage) {
          currentPackage.dependencies.push(...refs);
        }
        pendingDependencies = null;
        dependenciesBuffer = "";
      }
      continue;
    }

    if (isTableHeader(line)) {
      if (line === PACKAGE_TABLE) {
        flushCurrentPackage();
        inIgnoredTable = false;
        sawFirstPackage = true;
        currentPackage = { dependencies: [] };
      } else {
        flushCurrentPackage();
        inIgnoredTable = true;
        currentPackage = null;
        if (line === "[metadata]") {
          sawMetadataTable = true;
        }
      }
      continue;
    }

    if (inIgnoredTable) {
      continue;
    }

    const eqIndex = line.indexOf("=");
    if (eqIndex === -1) {
      continue;
    }

    const key = line.slice(0, eqIndex).trim();
    const valuePart = line.slice(eqIndex + 1).trim();

    if (!sawFirstPackage && key === "version") {
      const parsed = parseInt(parseStringValue(valuePart), 10);
      if (!Number.isNaN(parsed)) {
        explicitVersion = parsed;
      }
      continue;
    }

    if (!currentPackage) {
      continue;
    }

    switch (key) {
      case "name":
        currentPackage.name = parseStringValue(valuePart);
        break;
      case "version":
        currentPackage.version = parseStringValue(valuePart);
        break;
      case "source":
        currentPackage.source = parseStringValue(valuePart);
        break;
      case "checksum":
        break;
      case "dependencies":
        if (valuePart.startsWith("[") && !valuePart.endsWith("]")) {
          pendingDependencies = [];
          dependenciesBuffer = valuePart;
        } else if (valuePart.startsWith("[")) {
          const refs = extractQuotedStrings(valuePart).map(parseDependencyRef);
          currentPackage.dependencies.push(...refs);
        }
        break;
      default:
        break;
    }
  }

  flushCurrentPackage();

  // Cargo itself distinguishes v1 from v2 by the presence of an explicit
  // top-level `version` key. Absent that key, v1 lockfiles still carry a
  // `[metadata]` checksum table while v2 lockfiles carry neither.
  const lockfileVersion =
    explicitVersion !== undefined ? explicitVersion : sawMetadataTable ? 1 : 2;

  return { lockfileVersion, packages };
}
