export interface CargoLockDependency {
  name: string;
  version?: string;
}

export interface CargoLockPackage {
  name: string;
  version: string;
  source?: string;
  dependencies: CargoLockDependency[];
}

export function parseDependencyString(dep: string): CargoLockDependency | null {
  const trimmed = dep.trim();
  if (!trimmed) {
    return null;
  }

  const v1Match = trimmed.match(/^(\S+)\s+(\S+)\s+\((.+)\)$/);
  if (v1Match) {
    return { name: v1Match[1], version: v1Match[2] };
  }

  const parts = trimmed.split(/\s+/);
  const name = parts[0];
  const version = parts.length > 1 ? parts[1] : undefined;
  return { name, version };
}

function parseDependencyEntries(content: string, pkg: CargoLockPackage): void {
  const regex = /"([^"]*)"/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    const dep = parseDependencyString(match[1]);
    if (dep) {
      pkg.dependencies.push(dep);
    }
  }
}

export function parseCargoLock(content: string): CargoLockPackage[] {
  if (!content || !content.trim()) {
    return [];
  }

  try {
    const packages: CargoLockPackage[] = [];
    let current: CargoLockPackage | null = null;
    let inDependencies = false;
    let depBuffer = "";

    const lines = content.split("\n");

    for (const rawLine of lines) {
      const line = rawLine.trim();

      if (line.startsWith("#") || line === "") {
        continue;
      }

      if (line === "[metadata]") {
        if (current && current.name && current.version) {
          packages.push(current);
        }
        current = null;
        break;
      }

      if (line.startsWith("[[package]]")) {
        if (current && current.name && current.version) {
          packages.push(current);
        }
        current = { name: "", version: "", dependencies: [] };
        inDependencies = false;
        depBuffer = "";
        continue;
      }

      if (line.startsWith("[[") && !line.startsWith("[[package]]")) {
        if (current && current.name && current.version) {
          packages.push(current);
        }
        current = null;
        inDependencies = false;
        depBuffer = "";
        continue;
      }

      if (line.startsWith("[") && !line.startsWith("[[")) {
        if (current && current.name && current.version) {
          packages.push(current);
        }
        current = null;
        inDependencies = false;
        depBuffer = "";
        continue;
      }

      if (!current) {
        continue;
      }

      const nameMatch = line.match(/^name\s*=\s*"(.+)"$/);
      if (nameMatch) {
        current.name = nameMatch[1];
        continue;
      }

      const versionMatch = line.match(/^version\s*=\s*"(.+)"$/);
      if (versionMatch) {
        current.version = versionMatch[1];
        continue;
      }

      const sourceMatch = line.match(/^source\s*=\s*"(.+)"$/);
      if (sourceMatch) {
        current.source = sourceMatch[1];
        continue;
      }

      if (line.startsWith("dependencies = [")) {
        inDependencies = true;
        const inlineContent = line.slice("dependencies = [".length);
        if (inlineContent.includes("]")) {
          const inner = inlineContent.replace(/\]\s*,?\s*$/, "");
          parseDependencyEntries(inner, current);
          inDependencies = false;
          depBuffer = "";
        } else {
          depBuffer = inlineContent;
        }
        continue;
      }

      if (inDependencies) {
        if (line.includes("]")) {
          depBuffer += " " + line.replace(/\]\s*,?\s*$/, "");
          parseDependencyEntries(depBuffer, current);
          inDependencies = false;
          depBuffer = "";
        } else {
          depBuffer += " " + line.replace(/,\s*$/, "");
        }
      }
    }

    if (current && current.name && current.version) {
      packages.push(current);
    }

    return packages;
  } catch {
    return [];
  }
}
