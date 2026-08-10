import { DotnetPackage } from "./types";

function stripXmlComments(content: string): string {
  return content.replace(/<!--[\s\S]*?-->/g, "");
}

function isExactVersion(version: string): boolean {
  if (!version || version.includes("$(")) {
    return false;
  }
  if (version.includes("*")) {
    return false;
  }
  if (version.startsWith("[") || version.startsWith("(")) {
    return false;
  }
  return true;
}

function parsePackageReferenceTag(
  tagContent: string,
  packages: DotnetPackage[],
): void {
  if (/\bUpdate\s*=/i.test(tagContent)) {
    return;
  }

  const includeMatch = tagContent.match(/\bInclude\s*=\s*["']([^"']+)["']/i);
  if (!includeMatch) {
    return;
  }

  const name = includeMatch[1];
  let version: string | undefined;

  const versionAttrMatch = tagContent.match(
    /\bVersion\s*=\s*["']([^"']+)["']/i,
  );
  if (versionAttrMatch) {
    version = versionAttrMatch[1];
  } else {
    const childVersionMatch = tagContent.match(
      /<Version>\s*([^<]+?)\s*<\/Version>/i,
    );
    if (childVersionMatch) {
      version = childVersionMatch[1].trim();
    }
  }

  if (!version || !isExactVersion(version)) {
    return;
  }

  packages.push({ name, version });
}

export function parseProjectFile(content: string): DotnetPackage[] {
  if (!content || typeof content !== "string") {
    return [];
  }

  const stripped = stripXmlComments(content);
  const packages: DotnetPackage[] = [];

  const selfClosingRegex = /<PackageReference\b([^>]*)\/>/gi;
  let match: RegExpExecArray | null;
  while ((match = selfClosingRegex.exec(stripped)) !== null) {
    parsePackageReferenceTag(match[1], packages);
  }

  const elementRegex =
    /<PackageReference\b([^>]*[^/])>([\s\S]*?)<\/PackageReference>/gi;
  while ((match = elementRegex.exec(stripped)) !== null) {
    parsePackageReferenceTag(`${match[1]}>${match[2]}`, packages);
  }

  return packages;
}
