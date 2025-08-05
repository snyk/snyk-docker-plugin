import { SBOMDocument, SBOMPackage } from "../types";
import {
  extractNestedXMLStructure,
  extractXMLBlocks,
  extractXMLChecksums,
  extractXMLMultipleValues,
  extractXMLValue,
  isXMLContent,
  validateRequiredFields,
} from "../xml-utils";
import { BaseSPDXParser, SPDXPackage } from "./base-parser";

/**
 * SPDX XML format parser
 */
export class SPDXXMLParser extends BaseSPDXParser {
  constructor() {
    super("xml");
  }

  public canParse(content: string): boolean {
    if (!isXMLContent(content)) {
      return false;
    }

    return (
      content.includes("spdx:") ||
      content.includes("http://spdx.org") ||
      content.includes("<SpdxDocument")
    );
  }

  public parse(content: string): SBOMDocument | null {
    try {
      // Extract document-level information
      const documentName =
        extractXMLValue(content, ["spdx:name", "name"]) ||
        "Unknown SPDX XML Document";

      const spdxVersion =
        extractXMLValue(content, ["spdx:spdxVersion", "spdxVersion"]) ||
        "SPDX-2.2";

      const dataLicense =
        extractXMLValue(content, ["spdx:dataLicense", "dataLicense"]) ||
        "CC0-1.0";

      const documentNamespace = extractXMLValue(content, [
        "spdx:documentNamespace",
        "documentNamespace",
      ]);

      // Extract creation info
      const creationInfo = this.extractCreationInfo(content);

      // Extract packages
      const packages = this.extractPackages(content);

      // Process relationships for dependencies
      this.processRelationships(content, packages);

      return this.buildSBOMDocument(
        documentName,
        spdxVersion,
        dataLicense,
        documentNamespace,
        creationInfo,
        packages,
      );
    } catch (error) {
      return this.handleError(error, "XML");
    }
  }

  private extractCreationInfo(content: string) {
    const creationInfoBlocks = extractXMLBlocks(content, [
      "spdx:creationInfo",
      "creationInfo",
    ]);

    let created = "";
    let creators: string[] = [];
    let licenseListVersion: string | undefined;

    if (creationInfoBlocks.length > 0) {
      const creationInfoBlock = creationInfoBlocks[0];
      created =
        extractXMLValue(creationInfoBlock, ["spdx:created", "created"]) || "";
      creators = extractXMLMultipleValues(creationInfoBlock, [
        "spdx:creator",
        "creator",
      ]);
      licenseListVersion =
        extractXMLValue(creationInfoBlock, [
          "spdx:licenseListVersion",
          "licenseListVersion",
        ]) || undefined;
    }

    return this.buildCreationInfo(created, creators, licenseListVersion);
  }

  private extractPackages(content: string): SBOMPackage[] {
    const packageBlocks = extractXMLBlocks(content, [
      "spdx:Package",
      "Package",
    ]);
    const packages: SBOMPackage[] = [];

    for (const packageBlock of packageBlocks) {
      const packageData = this.parseXMLPackage(packageBlock);
      if (packageData) {
        packages.push(packageData);
      }
    }

    return packages;
  }

  private parseXMLPackage(packageBlock: string): SBOMPackage | null {
    const name = extractXMLValue(packageBlock, ["spdx:name", "name"]);

    if (!validateRequiredFields({ name }, ["name"])) {
      return null;
    }

    const versionInfo = extractXMLValue(packageBlock, [
      "spdx:versionInfo",
      "versionInfo",
    ]);

    const downloadLocation = extractXMLValue(packageBlock, [
      "spdx:downloadLocation",
      "downloadLocation",
    ]);

    const licenseConcluded = extractXMLValue(packageBlock, [
      "spdx:licenseConcluded",
      "licenseConcluded",
    ]);

    const licenseDeclared = extractXMLValue(packageBlock, [
      "spdx:licenseDeclared",
      "licenseDeclared",
    ]);

    const copyrightText = extractXMLValue(packageBlock, [
      "spdx:copyrightText",
      "copyrightText",
    ]);

    const supplier = extractXMLValue(packageBlock, [
      "spdx:supplier",
      "supplier",
    ]);

    const spdxId = extractXMLValue(packageBlock, ["spdx:SPDXID", "SPDXID"]);

    // Extract PURL from external references
    let purl: string | undefined;
    const externalRefStructures = extractNestedXMLStructure(
      packageBlock,
      "spdx:externalRef",
      [
        "spdx:referenceType",
        "spdx:referenceCategory",
        "spdx:referenceLocator",
        "referenceType",
        "referenceCategory",
        "referenceLocator",
      ],
    );

    for (const extRef of externalRefStructures) {
      const referenceType =
        extRef.referenceType || extRef["spdx:referenceType"];
      const referenceCategory =
        extRef.referenceCategory || extRef["spdx:referenceCategory"];
      const referenceLocator =
        extRef.referenceLocator || extRef["spdx:referenceLocator"];

      if (
        referenceType === "purl" ||
        (referenceCategory === "PACKAGE-MANAGER" && referenceType === "purl")
      ) {
        purl = referenceLocator;
        break;
      }
    }

    // Extract checksums using shared utility
    const checksums = extractXMLChecksums(
      packageBlock,
      ["spdx:checksum"],
      ["spdx:algorithm"],
      ["spdx:checksumValue"],
    );

    const spdxPackage: SPDXPackage = {
      SPDXID: spdxId || "",
      name: name!,
      versionInfo: this.extractVersion(versionInfo),
      downloadLocation: downloadLocation || undefined,
      licenseConcluded: this.normalizeLicense(licenseConcluded),
      licenseDeclared: this.normalizeLicense(licenseDeclared),
      copyrightText: copyrightText || undefined,
      supplier: this.extractSupplier(supplier),
      externalRefs: purl
        ? [
            {
              referenceCategory: "PACKAGE-MANAGER",
              referenceType: "purl",
              referenceLocator: purl,
            },
          ]
        : [],
      checksums: Object.entries(checksums).map(
        ([algorithm, checksumValue]) => ({
          algorithm,
          checksumValue,
        }),
      ),
    };

    return this.convertToSBOMPackage(spdxPackage);
  }

  private processRelationships(content: string, packages: any[]) {
    const relationshipBlocks = extractXMLBlocks(content, [
      "spdx:Relationship",
      "Relationship",
    ]);

    // Create a map for quick package lookup by SPDX ID
    const packageMap = new Map();
    packages.forEach((pkg, index) => {
      const spdxId = (pkg as any).spdxId;
      if (spdxId) {
        packageMap.set(spdxId, pkg);
      }
    });

    // Process relationships
    for (const relationshipBlock of relationshipBlocks) {
      const relationshipType = extractXMLValue(relationshipBlock, [
        "spdx:relationshipType",
        "relationshipType",
      ]);

      const spdxElementId = extractXMLValue(relationshipBlock, [
        "spdx:spdxElementId",
        "spdxElementId",
      ]);

      const relatedSpdxElement = extractXMLValue(relationshipBlock, [
        "spdx:relatedSpdxElement",
        "relatedSpdxElement",
      ]);

      // Process dependency relationships
      if (
        relationshipType === "DEPENDS_ON" &&
        spdxElementId &&
        relatedSpdxElement
      ) {
        const fromPkg = packageMap.get(spdxElementId);
        const toPkg = packageMap.get(relatedSpdxElement);

        if (fromPkg && toPkg) {
          fromPkg.dependencies = fromPkg.dependencies || [];
          fromPkg.dependencies.push(toPkg.name);
        }
      } else if (
        relationshipType === "DEPENDENCY_OF" &&
        spdxElementId &&
        relatedSpdxElement
      ) {
        const fromPkg = packageMap.get(relatedSpdxElement);
        const toPkg = packageMap.get(spdxElementId);

        if (fromPkg && toPkg) {
          fromPkg.dependencies = fromPkg.dependencies || [];
          fromPkg.dependencies.push(toPkg.name);
        }
      }
    }
  }
}
