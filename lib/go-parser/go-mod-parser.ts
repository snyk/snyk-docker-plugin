export interface GoModuleDependency {
  name: string;
  version: string;
}

export interface ParseGoModulesResult {
  modulePath: string;
  dependencies: GoModuleDependency[];
}

interface ReplaceDirective {
  oldModule: string;
  oldVersion?: string;
  newModule?: string;
  newVersion?: string;
  isLocal: boolean;
}

const VERSION_REGEX = /^v\d/;

export function parseGoModules(
  goModContent: string,
  goSumContent?: string,
): ParseGoModulesResult {
  const sumVersions = goSumContent ? parseGoSum(goSumContent) : new Map();
  const { modulePath, requires, replaces } = parseGoMod(goModContent);

  let dependencies = resolveDependencies(requires, sumVersions);
  dependencies = applyReplaces(dependencies, replaces);

  return { modulePath, dependencies };
}

function parseGoSum(content: string): Map<string, string[]> {
  const versions = new Map<string, string[]>();

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("//")) {
      continue;
    }

    const parts = line.split(/\s+/);
    if (parts.length < 2) {
      continue;
    }

    const modulePath = parts[0];
    let version = parts[1];
    if (version.endsWith("/go.mod")) {
      version = version.slice(0, -"/go.mod".length);
    }

    const existing = versions.get(modulePath) ?? [];
    if (!existing.includes(version)) {
      existing.push(version);
      versions.set(modulePath, existing);
    }
  }

  return versions;
}

function parseGoMod(content: string): {
  modulePath: string;
  requires: Map<string, string | undefined>;
  replaces: ReplaceDirective[];
} {
  let modulePath = "";
  const requires = new Map<string, string | undefined>();
  const replaces: ReplaceDirective[] = [];
  let blockType: "require" | "replace" | undefined;

  for (const rawLine of content.split("\n")) {
    const line = stripComment(rawLine).trim();
    if (!line) {
      continue;
    }

    if (blockType) {
      if (line === ")") {
        blockType = undefined;
        continue;
      }
      if (blockType === "require") {
        parseRequireEntry(line, requires);
      } else {
        const replace = parseReplaceEntry(line);
        if (replace) {
          replaces.push(replace);
        }
      }
      continue;
    }

    if (line.startsWith("module ")) {
      modulePath = line.slice("module ".length).trim();
      continue;
    }

    if (line === "require (" || line.startsWith("require(")) {
      blockType = "require";
      continue;
    }

    if (line === "replace (" || line.startsWith("replace(")) {
      blockType = "replace";
      continue;
    }

    if (line.startsWith("require ")) {
      parseRequireEntry(line.slice("require ".length).trim(), requires);
      continue;
    }

    if (line.startsWith("replace ")) {
      const replace = parseReplaceEntry(line.slice("replace ".length).trim());
      if (replace) {
        replaces.push(replace);
      }
    }
  }

  return { modulePath, requires, replaces };
}

function stripComment(line: string): string {
  const commentIndex = line.indexOf("//");
  if (commentIndex >= 0) {
    return line.slice(0, commentIndex);
  }
  return line;
}

function parseRequireEntry(
  line: string,
  requires: Map<string, string | undefined>,
): void {
  const parsed = parseModuleVersionLine(line);
  if (!parsed) {
    return;
  }
  requires.set(parsed.module, parsed.version);
}

function parseModuleVersionLine(
  line: string,
): { module: string; version?: string } | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length === 0) {
    return null;
  }

  if (parts.length === 1) {
    return { module: parts[0] };
  }

  const lastPart = parts[parts.length - 1];
  if (VERSION_REGEX.test(lastPart)) {
    return {
      module: parts.slice(0, -1).join(" "),
      version: lastPart,
    };
  }

  return { module: parts.join(" ") };
}

function parseReplaceEntry(line: string): ReplaceDirective | null {
  const arrowIndex = line.indexOf("=>");
  if (arrowIndex < 0) {
    return null;
  }

  const left = line.slice(0, arrowIndex).trim();
  const right = line.slice(arrowIndex + 2).trim();
  if (!left || !right) {
    return null;
  }

  const leftParsed = parseModuleVersionLine(left);
  if (!leftParsed) {
    return null;
  }

  const rightParts = right.split(/\s+/);
  if (rightParts.length === 1 && isLocalPath(rightParts[0])) {
    return {
      oldModule: leftParsed.module,
      oldVersion: leftParsed.version,
      isLocal: true,
    };
  }

  const rightParsed = parseModuleVersionLine(right);
  if (!rightParsed?.version) {
    return null;
  }

  return {
    oldModule: leftParsed.module,
    oldVersion: leftParsed.version,
    newModule: rightParsed.module,
    newVersion: rightParsed.version,
    isLocal: false,
  };
}

function isLocalPath(path: string): boolean {
  return (
    path.startsWith("./") || path.startsWith("../") || path.startsWith("/")
  );
}

function resolveDependencies(
  requires: Map<string, string | undefined>,
  sumVersions: Map<string, string[]>,
): GoModuleDependency[] {
  const dependencies: GoModuleDependency[] = [];

  for (const [name, modVersion] of requires) {
    let version = modVersion;

    if (!version) {
      const sumEntries = sumVersions.get(name);
      if (sumEntries && sumEntries.length > 0) {
        version = sumEntries[0];
      }
    }

    if (version) {
      dependencies.push({ name, version });
    }
  }

  return dependencies;
}

function applyReplaces(
  dependencies: GoModuleDependency[],
  replaces: ReplaceDirective[],
): GoModuleDependency[] {
  let result = dependencies;

  for (const replace of replaces) {
    result = result.flatMap((dep) => {
      if (dep.name !== replace.oldModule) {
        return [dep];
      }

      if (replace.oldVersion && dep.version !== replace.oldVersion) {
        return [dep];
      }

      if (replace.isLocal) {
        return [];
      }

      return [
        {
          name: replace.newModule!,
          version: replace.newVersion!,
        },
      ];
    });
  }

  return result;
}
