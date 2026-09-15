import * as Debug from "debug";

const debug = Debug("snyk-docker-plugin:cargo-lock-parser");

export interface CargoLockPackage {
  name: string;
  version: string;
  source?: string;
  dependencies: string[];
}

export interface CargoLockParseResult {
  lockfileVersion: number;
  packages: CargoLockPackage[];
}

export class CargoLockParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CargoLockParseError";
  }
}

type TomlPrimitive = string | number | boolean;
type TomlValue = TomlPrimitive | TomlValue[] | TomlTable | TomlTable[];
interface TomlTable {
  [key: string]: TomlValue;
}

export function parseCargoLock(content: string): CargoLockParseResult {
  if (!content || !content.trim()) {
    throw new CargoLockParseError("Empty Cargo.lock content");
  }

  let document: TomlTable;
  try {
    document = parseTomlDocument(content);
  } catch (err) {
    throw new CargoLockParseError(
      err instanceof Error ? err.message : "Failed to parse Cargo.lock",
    );
  }

  const lockfileVersion =
    typeof document.version === "number" ? document.version : 1;

  const rawPackages = document.package;
  if (!rawPackages) {
    return { lockfileVersion, packages: [] };
  }

  if (!Array.isArray(rawPackages)) {
    throw new CargoLockParseError(
      "Invalid Cargo.lock: [[package]] must be an array of tables",
    );
  }

  const packages: CargoLockPackage[] = [];
  for (const entry of rawPackages) {
    if (!isTomlTable(entry)) {
      continue;
    }
    const name = entry.name;
    const version = entry.version;
    if (typeof name !== "string" || typeof version !== "string") {
      debug("Skipping package entry missing name or version");
      continue;
    }

    const source = typeof entry.source === "string" ? entry.source : undefined;
    const dependencies = parseDependenciesArray(entry.dependencies);

    packages.push({ name, version, source, dependencies });
  }

  return { lockfileVersion, packages };
}

function parseDependenciesArray(value: TomlValue | undefined): string[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  const deps: string[] = [];
  for (const item of value) {
    if (typeof item === "string") {
      deps.push(item);
    }
  }
  return deps;
}

function isTomlTable(value: TomlValue): value is TomlTable {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Array)
  );
}

function parseTomlDocument(content: string): TomlTable {
  const root: TomlTable = {};
  const tableStack: Array<{ table: TomlTable; isArray: boolean }> = [
    { table: root, isArray: false },
  ];

  const lines = splitTomlLines(content);
  let lineIndex = 0;

  while (lineIndex < lines.length) {
    const rawLine = lines[lineIndex];
    const line = stripComment(rawLine).trim();

    if (!line) {
      lineIndex++;
      continue;
    }

    if (line.startsWith("[[")) {
      const header = line.slice(2, -2).trim();
      if (header === "patch.unused") {
        lineIndex++;
        while (lineIndex < lines.length) {
          const next = stripComment(lines[lineIndex]).trim();
          if (
            next.startsWith("[[") ||
            (next.startsWith("[") && !next.startsWith("[["))
          ) {
            break;
          }
          lineIndex++;
        }
        continue;
      }

      const key = header.split(".")[0];
      if (!root[key]) {
        root[key] = [];
      }
      const arr = root[key];
      if (!Array.isArray(arr)) {
        throw new Error(`Table conflict for [[${header}]]`);
      }

      const newTable: TomlTable = {};
      arr.push(newTable);
      tableStack.length = 1;
      tableStack.push({ table: newTable, isArray: true });
      lineIndex++;
      continue;
    }

    if (line.startsWith("[")) {
      const header = line.slice(1, -1).trim();
      if (header === "metadata") {
        lineIndex++;
        while (lineIndex < lines.length) {
          const next = stripComment(lines[lineIndex]).trim();
          if (next.startsWith("[[")) {
            break;
          }
          if (next.startsWith("[") && !next.startsWith("[[")) {
            break;
          }
          lineIndex++;
        }
        continue;
      }

      tableStack.length = 1;
      const table = getOrCreateTable(root, header);
      tableStack.push({ table, isArray: false });
      lineIndex++;
      continue;
    }

    const eqIndex = line.indexOf("=");
    if (eqIndex === -1) {
      throw new Error(`Invalid TOML line: ${rawLine}`);
    }

    const key = line.slice(0, eqIndex).trim();
    let valueStr = line.slice(eqIndex + 1).trim();

    if (valueStr.startsWith("[") && !valueStr.endsWith("]")) {
      const arrayLines = [valueStr];
      lineIndex++;
      while (lineIndex < lines.length) {
        const nextLine = stripComment(lines[lineIndex]).trim();
        arrayLines.push(nextLine);
        if (nextLine.endsWith("]")) {
          break;
        }
        lineIndex++;
      }
      valueStr = arrayLines.join("\n");
    } else if (valueStr.startsWith('"""') && !valueStr.endsWith('"""')) {
      const mlLines = [valueStr];
      lineIndex++;
      while (lineIndex < lines.length) {
        const nextLine = lines[lineIndex];
        mlLines.push(nextLine);
        if (nextLine.includes('"""')) {
          break;
        }
        lineIndex++;
      }
      valueStr = mlLines.join("\n");
    }

    const value = parseTomlValue(valueStr);
    const current = tableStack[tableStack.length - 1].table;
    current[key] = value;
    lineIndex++;
  }

  return root;
}

function getOrCreateTable(root: TomlTable, dottedKey: string): TomlTable {
  const parts = dottedKey.split(".");
  let current = root;
  for (const part of parts) {
    const existing = current[part];
    if (existing === undefined) {
      const newTable: TomlTable = {};
      current[part] = newTable;
      current = newTable;
    } else if (isTomlTable(existing)) {
      current = existing;
    } else {
      throw new Error(`Table conflict for [${dottedKey}]`);
    }
  }
  return current;
}

function splitTomlLines(content: string): string[] {
  const lines: string[] = [];
  let current = "";
  let inTripleQuote = false;

  for (const rawLine of content.split(/\r?\n/)) {
    if (inTripleQuote) {
      current += (current ? "\n" : "") + rawLine;
      if (rawLine.includes('"""')) {
        lines.push(current);
        current = "";
        inTripleQuote = false;
      }
      continue;
    }

    const trimmed = rawLine.trim();
    if (trimmed.startsWith('"""') && !trimmed.endsWith('"""', 3)) {
      inTripleQuote = true;
      current = rawLine;
      continue;
    }

    lines.push(rawLine);
  }

  if (current) {
    lines.push(current);
  }

  return lines;
}

function stripComment(line: string): string {
  let inString = false;
  let stringChar = "";
  let escaped = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\" && inString) {
      escaped = true;
      continue;
    }
    if (!inString && (ch === '"' || ch === "'")) {
      inString = true;
      stringChar = ch;
      continue;
    }
    if (inString && ch === stringChar) {
      inString = false;
      stringChar = "";
      continue;
    }
    if (!inString && ch === "#") {
      return line.slice(0, i);
    }
  }

  return line;
}

function parseTomlValue(raw: string): TomlValue {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Missing TOML value");
  }

  if (trimmed.startsWith("[")) {
    return parseTomlArray(trimmed);
  }

  if (trimmed.startsWith('"""')) {
    return parseMultilineBasicString(trimmed);
  }

  if (trimmed.startsWith('"')) {
    return parseBasicString(trimmed);
  }

  if (trimmed.startsWith("'")) {
    return parseLiteralString(trimmed);
  }

  if (trimmed === "true") {
    return true;
  }
  if (trimmed === "false") {
    return false;
  }

  if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(trimmed)) {
    return Number(trimmed);
  }

  throw new Error(`Unsupported TOML value: ${trimmed}`);
}

function parseTomlArray(raw: string): TomlValue[] {
  const inner = raw.trim().slice(1, -1).trim();
  if (!inner) {
    return [];
  }

  const items: TomlValue[] = [];
  let current = "";
  let inString = false;
  let stringChar = "";
  let escaped = false;
  let depth = 0;

  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (inString && ch === "\\") {
      current += ch;
      escaped = true;
      continue;
    }
    if (!inString && (ch === '"' || ch === "'")) {
      inString = true;
      stringChar = ch;
      current += ch;
      continue;
    }
    if (inString && ch === stringChar) {
      inString = false;
      stringChar = "";
      current += ch;
      continue;
    }
    if (!inString) {
      if (ch === "[") {
        depth++;
      } else if (ch === "]") {
        depth--;
      } else if (ch === "," && depth === 0) {
        items.push(parseTomlValue(current.trim()));
        current = "";
        continue;
      }
    }
    current += ch;
  }

  if (current.trim()) {
    items.push(parseTomlValue(current.trim()));
  }

  return items;
}

function parseBasicString(raw: string): string {
  let result = "";
  let i = 1;
  while (i < raw.length) {
    const ch = raw[i];
    if (ch === "\\") {
      const next = raw[i + 1];
      switch (next) {
        case "n":
          result += "\n";
          break;
        case "t":
          result += "\t";
          break;
        case "r":
          result += "\r";
          break;
        case "\\":
          result += "\\";
          break;
        case '"':
          result += '"';
          break;
        case "u": {
          const hex = raw.slice(i + 2, i + 6);
          result += String.fromCharCode(parseInt(hex, 16));
          i += 4;
          break;
        }
        default:
          result += next;
      }
      i += 2;
      continue;
    }
    if (ch === '"') {
      break;
    }
    result += ch;
    i++;
  }
  return result;
}

function parseLiteralString(raw: string): string {
  if (raw.startsWith("'''")) {
    return raw.slice(3, -3);
  }
  return raw.slice(1, -1).replace(/''/g, "'");
}

function parseMultilineBasicString(raw: string): string {
  const inner = raw.slice(3, -3);
  return inner.replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\"/g, '"');
}

export function parseDependencyRef(dep: string): {
  name: string;
  version?: string;
  source?: string;
} {
  const trimmed = dep.trim();
  const parenStart = trimmed.lastIndexOf(" (");
  if (parenStart !== -1 && trimmed.endsWith(")")) {
    const source = trimmed.slice(parenStart + 2, -1);
    const before = trimmed.slice(0, parenStart);
    const spaceIdx = before.lastIndexOf(" ");
    if (spaceIdx !== -1) {
      return {
        name: before.slice(0, spaceIdx),
        version: before.slice(spaceIdx + 1),
        source,
      };
    }
    return { name: before, source };
  }

  const spaceIdx = trimmed.lastIndexOf(" ");
  if (spaceIdx !== -1) {
    return {
      name: trimmed.slice(0, spaceIdx),
      version: trimmed.slice(spaceIdx + 1),
    };
  }

  return { name: trimmed };
}

export function resolveDependencyPackage(
  depRef: { name: string; version?: string; source?: string },
  packages: CargoLockPackage[],
): CargoLockPackage | undefined {
  const candidates = packages.filter((p) => p.name === depRef.name);
  if (candidates.length === 0) {
    return undefined;
  }

  if (depRef.version) {
    let filtered = candidates.filter((p) => p.version === depRef.version);
    if (depRef.source) {
      filtered = filtered.filter((p) => p.source === depRef.source);
    }
    if (filtered.length === 1) {
      return filtered[0];
    }
    return undefined;
  }

  if (depRef.source) {
    const filtered = candidates.filter((p) => p.source === depRef.source);
    if (filtered.length === 1) {
      return filtered[0];
    }
    return undefined;
  }

  if (candidates.length === 1) {
    return candidates[0];
  }

  return undefined;
}
