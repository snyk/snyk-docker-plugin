import { CargoPackage, CargoPackageDependency } from "./types";

// Hand-rolled parser for the Cargo.lock TOML subset: array-of-tables headers
// ([[package]]), key = "string" pairs, and inline or multi-line string arrays for
// dependencies. Unlike lib/go-parser/go-mod-parser.ts, which may return partial
// results from a malformed document, this parser returns [] on any syntax failure.

class CargoLockParseError extends Error {}

export function parseCargoLock(
  content: string | undefined | null,
): CargoPackage[] {
  if (content == null || content === "") {
    return [];
  }

  try {
    return parseCargoLockInternal(content);
  } catch (error) {
    if (error instanceof CargoLockParseError) {
      return [];
    }
    throw error;
  }
}

function parseCargoLockInternal(content: string): CargoPackage[] {
  const packages: CargoPackage[] = [];
  let currentPackage: Partial<CargoPackage> | null = null;
  let inSkippedTable = false;
  let openArray: "dependencies" | null = null;
  let openArrayItems: CargoPackageDependency[] = [];

  const lines = content.split("\n");

  for (const rawLine of lines) {
    const line = stripComment(rawLine).trim();

    if (openArray) {
      if (!line) {
        continue;
      }

      if (line === "]" || line === "],") {
        if (currentPackage && openArray === "dependencies") {
          currentPackage.dependencies = openArrayItems;
        }
        openArray = null;
        openArrayItems = [];
        continue;
      }

      for (const entry of parseArrayLineEntries(line)) {
        openArrayItems.push(parseDependencyString(entry));
      }
      continue;
    }

    if (!line) {
      continue;
    }

    if (line.startsWith("[")) {
      if (currentPackage && !inSkippedTable) {
        finalizePackage(currentPackage, packages);
      }

      const headerType = parseTableHeader(line);
      if (headerType === "package") {
        currentPackage = { dependencies: [] };
        inSkippedTable = false;
      } else {
        currentPackage = null;
        inSkippedTable = true;
      }
      continue;
    }

    if (inSkippedTable || !currentPackage) {
      continue;
    }

    const keyValue = parseKeyValue(line);
    if (!keyValue) {
      throw new CargoLockParseError();
    }

    const { key, value } = keyValue;

    if (key === "name") {
      currentPackage.name = parseStringValue(value);
      continue;
    }

    if (key === "version") {
      currentPackage.version = parseStringValue(value);
      continue;
    }

    if (key === "dependencies") {
      const dependencyAssignment = assignDependencies(value);
      if (dependencyAssignment.type === "inline") {
        currentPackage.dependencies = dependencyAssignment.dependencies;
      } else {
        openArray = "dependencies";
        openArrayItems = dependencyAssignment.initialItems;
      }
      continue;
    }

    // Skip checksum, source, replace, and other unrecognised keys.
  }

  if (openArray) {
    throw new CargoLockParseError();
  }

  if (currentPackage && !inSkippedTable) {
    finalizePackage(currentPackage, packages);
  }

  return packages;
}

function parseTableHeader(line: string): "package" | "skip" {
  if (line.startsWith("[[")) {
    if (!line.endsWith("]]")) {
      throw new CargoLockParseError();
    }

    const inner = line.slice(2, -2);
    if (inner.includes("[") || inner.includes("]")) {
      throw new CargoLockParseError();
    }

    if (inner === "package") {
      return "package";
    }

    return "skip";
  }

  if (!line.endsWith("]") || line.endsWith("]]")) {
    throw new CargoLockParseError();
  }

  const inner = line.slice(1, -1);
  if (inner.includes("[") || inner.includes("]")) {
    throw new CargoLockParseError();
  }

  return "skip";
}

function parseKeyValue(line: string): { key: string; value: string } | null {
  const equalsIndex = line.indexOf("=");
  if (equalsIndex < 0) {
    return null;
  }

  const key = line.slice(0, equalsIndex).trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(key)) {
    return null;
  }

  return {
    key,
    value: line.slice(equalsIndex + 1).trim(),
  };
}

function parseStringValue(valuePart: string): string {
  if (!valuePart.startsWith('"')) {
    throw new CargoLockParseError();
  }

  let index = 1;
  while (index < valuePart.length) {
    if (valuePart[index] === "\\") {
      index += 2;
      continue;
    }

    if (valuePart[index] === '"') {
      return valuePart.slice(1, index);
    }

    index++;
  }

  throw new CargoLockParseError();
}

type DependencyAssignment =
  | { type: "inline"; dependencies: CargoPackageDependency[] }
  | { type: "multiline"; initialItems: CargoPackageDependency[] };

function assignDependencies(value: string): DependencyAssignment {
  const trimmed = value.trim();

  if (trimmed === "[]") {
    return { type: "inline", dependencies: [] };
  }

  if (!trimmed.startsWith("[")) {
    throw new CargoLockParseError();
  }

  if (trimmed.endsWith("]") && trimmed.length > 1) {
    return {
      type: "inline",
      dependencies: parseArrayContent(trimmed.slice(1, -1)).map(
        parseDependencyString,
      ),
    };
  }

  const remainder = trimmed.slice(1).trim();
  const initialItems = remainder
    ? parseArrayContent(remainder).map(parseDependencyString)
    : [];

  return { type: "multiline", initialItems };
}

function parseArrayContent(content: string): string[] {
  const entries: string[] = [];
  let index = 0;

  while (index < content.length) {
    while (index < content.length && /[\s,]/.test(content[index])) {
      index++;
    }

    if (index >= content.length) {
      break;
    }

    if (content[index] !== '"') {
      throw new CargoLockParseError();
    }

    index++;
    const start = index;
    let closed = false;

    while (index < content.length) {
      if (content[index] === "\\") {
        index += 2;
        continue;
      }

      if (content[index] === '"') {
        entries.push(content.slice(start, index));
        index++;
        closed = true;
        break;
      }

      index++;
    }

    if (!closed) {
      throw new CargoLockParseError();
    }
  }

  return entries;
}

function parseArrayLineEntries(line: string): string[] {
  return parseArrayContent(line.replace(/,\s*$/, ""));
}

function parseDependencyString(value: string): CargoPackageDependency {
  let dependencyText = value.trim();
  const parenthesisIndex = dependencyText.indexOf(" (");

  if (parenthesisIndex >= 0) {
    dependencyText = dependencyText.slice(0, parenthesisIndex);
  }

  const parts = dependencyText.trim().split(/\s+/);
  if (parts.length === 1) {
    return { name: parts[0] };
  }

  return {
    name: parts[0],
    version: parts[1],
  };
}

function finalizePackage(
  currentPackage: Partial<CargoPackage>,
  packages: CargoPackage[],
): void {
  packages.push({
    name: currentPackage.name ?? "",
    version: currentPackage.version ?? "",
    dependencies: currentPackage.dependencies ?? [],
  });
}

function stripComment(line: string): string {
  let inString = false;

  for (let index = 0; index < line.length; index++) {
    const char = line[index];

    if (inString && char === "\\") {
      index++;
      continue;
    }

    if (char === '"') {
      inString = !inString;
      continue;
    }

    if (char === "#" && !inString) {
      return line.slice(0, index);
    }
  }

  return line;
}
