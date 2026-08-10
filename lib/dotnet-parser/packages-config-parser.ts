import { DotnetPackage } from "./types";

const PACKAGE_TAG_REGEX =
  /<package\b[^>]*\bid\s*=\s*["']([^"']+)["'][^>]*\bversion\s*=\s*["']([^"']+)["'][^>]*\/?>/gi;

function isDevelopmentDependency(tag: string): boolean {
  const match = tag.match(/\bdevelopmentDependency\s*=\s*["']([^"']+)["']/i);
  return match !== null && match[1].toLowerCase() === "true";
}

export function parsePackagesConfig(content: string): DotnetPackage[] {
  if (!content || typeof content !== "string") {
    return [];
  }

  const packages: DotnetPackage[] = [];
  let match: RegExpExecArray | null;

  PACKAGE_TAG_REGEX.lastIndex = 0;
  while ((match = PACKAGE_TAG_REGEX.exec(content)) !== null) {
    const fullTag = match[0];
    if (isDevelopmentDependency(fullTag)) {
      continue;
    }

    packages.push({
      name: match[1],
      version: match[2],
    });
  }

  return packages;
}
