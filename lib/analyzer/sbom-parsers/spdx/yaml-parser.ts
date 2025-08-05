import { SBOMDocument, SBOMPackage } from "../types";
import { BaseSPDXParser, SPDXPackage } from "./base-parser";

/**
 * SPDX YAML format parser
 */
export class SPDXYAMLParser extends BaseSPDXParser {
  constructor() {
    super("yaml");
  }

  public canParse(content: string): boolean {
    return (
      content.includes(":") &&
      (content.includes("spdx") || content.includes("SPDX")) &&
      (content.includes("---") ||
        content.includes("spdxVersion") ||
        content.includes("dataLicense"))
    );
  }

  public parse(content: string): SBOMDocument | null {
    try {
      // Simple YAML-to-JSON conversion for SPDX documents
      // This handles basic YAML structures commonly found in SPDX files
      const processedContent = content
        .replace(/^\s*---\s*$/gm, "") // Remove YAML document separators
        .replace(/^\s*\.\.\.\s*$/gm, "") // Remove YAML document end markers
        .replace(/^\s*#.*$/gm, "") // Remove comments
        .replace(/^\s*$/gm, ""); // Remove empty lines

      // Extract basic document structure
      const lines = processedContent.split("\n").filter((line) => line.trim());
      const documentData: any = {};
      const packages: any[] = [];
      let currentSection = "document";
      let currentPackage: any = null;
      let indentLevel = 0;

      for (const line of lines) {
        const trimmed = line.trim();

        if (!trimmed) {
          continue;
        }

        // Calculate indentation level
        const currentIndent = line.length - line.trimLeft().length;

        // Handle different sections
        if (trimmed.match(/^(spdx_?version|specVersion):/i)) {
          documentData.version =
            this.extractYAMLValue(trimmed.split(":")[1]) || "SPDX-2.2";
        } else if (trimmed.match(/^(data_?license|dataLicense):/i)) {
          documentData.dataLicense =
            this.extractYAMLValue(trimmed.split(":")[1]) || "CC0-1.0";
        } else if (trimmed.match(/^(document_?name|name):/i)) {
          documentData.name =
            this.extractYAMLValue(trimmed.split(":")[1]) ||
            "Unknown SPDX YAML Document";
        } else if (
          trimmed.match(/^(document_?namespace|documentNamespace):/i)
        ) {
          documentData.documentNamespace = this.extractYAMLValue(
            trimmed.split(":")[1],
          );
        } else if (trimmed.match(/^(creation_?info|creationInfo):/i)) {
          currentSection = "creationInfo";
          documentData.creationInfo = {};
        } else if (trimmed.match(/^(packages?):/i)) {
          currentSection = "packages";
        } else if (currentSection === "creationInfo") {
          if (trimmed.match(/^(created?):/i)) {
            documentData.creationInfo.created =
              this.extractYAMLValue(trimmed.split(":")[1]) || "";
          } else if (trimmed.match(/^(creators?|creator):/i)) {
            const value = this.extractYAMLValue(trimmed.split(":")[1]);
            if (value) {
              documentData.creationInfo.creators = Array.isArray(value)
                ? value
                : [value];
            }
          } else if (
            trimmed.match(/^(license_?list_?version|licenseListVersion):/i)
          ) {
            documentData.creationInfo.licenseListVersion =
              this.extractYAMLValue(trimmed.split(":")[1]);
          }
        } else if (currentSection === "packages") {
          if (
            trimmed.startsWith("- ") ||
            (currentIndent <= indentLevel && trimmed.includes(":"))
          ) {
            // New package
            if (currentPackage) {
              packages.push(currentPackage);
            }
            currentPackage = {};
            indentLevel = currentIndent;

            if (trimmed.startsWith("- ")) {
              const nameMatch = trimmed.match(/^-\s*(.*?):\s*(.*)$/);
              if (nameMatch) {
                currentPackage[nameMatch[1]] =
                  this.extractYAMLValue(nameMatch[2]) || nameMatch[2];
              }
            } else {
              const nameMatch = trimmed.match(/^(.*?):\s*(.*)$/);
              if (nameMatch) {
                currentPackage[nameMatch[1]] =
                  this.extractYAMLValue(nameMatch[2]) || nameMatch[2];
              }
            }
          } else if (currentPackage && currentIndent > indentLevel) {
            // Package property
            const propertyMatch = trimmed.match(/^(.*?):\s*(.*)$/);
            if (propertyMatch) {
              const key = propertyMatch[1].trim();
              const value =
                this.extractYAMLValue(propertyMatch[2]) || propertyMatch[2];
              currentPackage[key] = value;
            }
          }
        }
      }

      // Add last package
      if (currentPackage) {
        packages.push(currentPackage);
      }

      // Convert to SPDX format
      const spdxPackages = this.convertYAMLPackages(packages);

      return this.buildSBOMDocument(
        documentData.name || "Unknown SPDX YAML Document",
        documentData.version || "SPDX-2.2",
        documentData.dataLicense || "CC0-1.0",
        documentData.documentNamespace,
        documentData.creationInfo || this.buildCreationInfo("", []),
        spdxPackages,
      );
    } catch (error) {
      return this.handleError(error, "YAML");
    }
  }

  private convertYAMLPackages(packages: any[]): SBOMPackage[] {
    return packages
      .map((pkg) => {
        if (!this.validatePackage(pkg)) {
          return null;
        }

        const spdxPackage: SPDXPackage = {
          SPDXID: pkg.SPDXID || "",
          name: pkg.name || pkg.packageName || "unknown",
          versionInfo: this.extractVersion(pkg.version || pkg.versionInfo),
          downloadLocation: pkg.downloadLocation,
          licenseConcluded: this.normalizeLicense(pkg.licenseConcluded),
          licenseDeclared: this.normalizeLicense(
            pkg.licenseDeclared || pkg.license,
          ),
          copyrightText: pkg.copyrightText,
          supplier: this.extractSupplier(pkg.supplier),
          externalRefs:
            pkg.purl || pkg.packageURL
              ? [
                  {
                    referenceCategory: "PACKAGE-MANAGER",
                    referenceType: "purl",
                    referenceLocator: pkg.purl || pkg.packageURL,
                  },
                ]
              : [],
          checksums: Array.isArray(pkg.checksums) ? pkg.checksums : [],
        };

        return this.convertToSBOMPackage(spdxPackage);
      })
      .filter((pkg): pkg is SBOMPackage => pkg !== null);
  }

  /**
   * Extract YAML value handling different formats
   */
  private extractYAMLValue(valueStr: string): string | null {
    if (!valueStr) {
      return null;
    }

    const trimmed = valueStr.trim();

    // Handle quoted strings
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))
    ) {
      return trimmed.slice(1, -1);
    }

    // Handle special YAML values
    if (trimmed === "null" || trimmed === "~" || trimmed === "") {
      return null;
    }

    if (trimmed === "true" || trimmed === "false") {
      return trimmed;
    }

    // Return as string
    return trimmed || null;
  }
}
