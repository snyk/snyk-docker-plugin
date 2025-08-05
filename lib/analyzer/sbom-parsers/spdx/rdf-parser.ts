import { SBOMDocument, SBOMPackage } from "../types";
import {
  extractNestedXMLStructure,
  extractXMLAttribute,
  extractXMLBlocks,
  extractXMLChecksums,
  extractXMLMultipleValues,
  extractXMLValue,
  isXMLContent,
  validateRequiredFields,
} from "../xml-utils";
import { BaseSPDXParser, SPDXPackage } from "./base-parser";

/**
 * SPDX RDF/XML format parser
 */
export class SPDXRDFParser extends BaseSPDXParser {
  constructor() {
    super("rdf");
  }

  public canParse(content: string): boolean {
    if (!isXMLContent(content)) {
      return false;
    }

    return (
      (content.includes("rdf:") ||
        content.includes("spdx:") ||
        content.includes("http://spdx.org")) &&
      (content.includes("RDF") || content.includes("rdf"))
    );
  }

  public parse(content: string): SBOMDocument | null {
    try {
      // Extract document-level information
      const documentName =
        extractXMLValue(content, ["spdx:name", "name"]) ||
        extractXMLValue(content, ["rdf:Description", "spdx:SpdxDocument"]) ||
        "Unknown SPDX RDF Document";

      const spdxVersion =
        extractXMLValue(content, ["spdx:specVersion", "specVersion"]) ||
        "SPDX-2.2";
      const dataLicense =
        extractXMLValue(content, ["spdx:dataLicense", "dataLicense"]) ||
        "CC0-1.0";
      const documentNamespace = extractXMLValue(content, [
        "spdx:documentNamespace",
        "documentNamespace",
      ]);

      // Extract creation info from RDF
      const creationInfo = this.extractCreationInfo(content);

      // Extract packages from RDF (can be nested in various ways)
      const packages = this.extractPackages(content);

      // Process relationships for dependencies (RDF style)
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
      return this.handleError(error, "RDF");
    }
  }

  private extractCreationInfo(content: string) {
    // Look for creation info in RDF Description or spdx:CreationInfo
    const creationInfoBlocks = extractXMLBlocks(content, [
      "spdx:CreationInfo",
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

      // Extract multiple creators (can be in different RDF formats)
      creators = extractXMLMultipleValues(creationInfoBlock, [
        "spdx:creator",
        "creator",
      ]);

      const licenseListVersionValue = extractXMLValue(creationInfoBlock, [
        "spdx:licenseListVersion",
        "licenseListVersion",
      ]);
      if (licenseListVersionValue) {
        licenseListVersion = licenseListVersionValue;
      }
    }

    return this.buildCreationInfo(created, creators, licenseListVersion);
  }

  private extractPackages(content: string): SBOMPackage[] {
    // Look for spdx:Package elements or rdf:Description with spdx:Package type
    const packageBlocks = [
      ...extractXMLBlocks(content, ["spdx:Package"]),
      ...extractXMLBlocks(content, ["rdf:Description"]).filter(
        (block) =>
          block.includes("rdf:type") &&
          (block.includes("spdx:Package") ||
            block.includes("http://spdx.org/rdf/terms#Package")),
      ),
    ];

    const packages: SBOMPackage[] = [];
    for (const packageBlock of packageBlocks) {
      const packageData = this.parseRDFPackage(packageBlock);
      if (packageData) {
        packages.push(packageData);
      }
    }

    return packages;
  }

  private parseRDFPackage(packageBlock: string): SBOMPackage | null {
    const name = extractXMLValue(packageBlock, ["spdx:name", "name"]);

    if (!validateRequiredFields({ name }, ["name"])) {
      return null;
    }

    const versionInfo = extractXMLValue(packageBlock, [
      "spdx:versionInfo",
      "versionInfo",
      "spdx:version",
      "version",
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

    // Extract SPDX ID for relationship processing (RDF resource references)
    const spdxId =
      extractXMLValue(packageBlock, ["spdx:spdxId", "spdxId"]) ||
      extractXMLAttribute(packageBlock, "rdf:Description", "rdf:about") ||
      extractXMLAttribute(packageBlock, "spdx:Package", "rdf:about");

    // Extract PURL from external references (RDF style)
    let purl: string | undefined;
    const externalRefStructures = extractNestedXMLStructure(
      packageBlock,
      "spdx:externalRef",
      ["spdx:referenceType", "spdx:referenceCategory", "spdx:referenceLocator"],
    );

    for (const extRef of externalRefStructures) {
      const referenceType = extRef["spdx:referenceType"];
      const referenceCategory = extRef["spdx:referenceCategory"];
      const referenceLocator = extRef["spdx:referenceLocator"];

      if (
        (referenceType === "purl" || referenceCategory === "PACKAGE-MANAGER") &&
        referenceLocator
      ) {
        purl = referenceLocator;
        break;
      }
    }

    // Extract checksums using shared utility (RDF style)
    const checksums = extractXMLChecksums(
      packageBlock,
      ["spdx:checksum"],
      ["spdx:algorithm"],
      ["spdx:checksumValue"],
    );

    const spdxPackage: SPDXPackage = {
      SPDXID: spdxId ? spdxId.replace(/^#/, "").replace(/.*#/, "") : "",
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
    const relationshipBlocks = [
      ...extractXMLBlocks(content, ["spdx:Relationship"]),
      ...extractXMLBlocks(content, ["rdf:Description"]).filter(
        (block) =>
          block.includes("rdf:type") &&
          (block.includes("spdx:Relationship") ||
            block.includes("http://spdx.org/rdf/terms#Relationship")),
      ),
    ];

    const packageMap = new Map();

    // Create mapping from SPDX IDs to packages
    packages.forEach((pkg) => {
      const spdxId = (pkg as any).spdxId;
      if (spdxId) {
        packageMap.set(spdxId, pkg);
      }
    });

    // Process RDF relationships
    for (const relationshipBlock of relationshipBlocks) {
      const relationshipType = extractXMLValue(relationshipBlock, [
        "spdx:relationshipType",
        "relationshipType",
      ]);

      // Extract subject and object of the relationship (RDF resource references)
      const spdxElementId =
        extractXMLValue(relationshipBlock, [
          "spdx:spdxElementId",
          "spdxElementId",
        ]) ||
        extractXMLAttribute(relationshipBlock, "rdf:Description", "rdf:about");

      const relatedSpdxElement =
        extractXMLValue(relationshipBlock, [
          "spdx:relatedSpdxElement",
          "relatedSpdxElement",
        ]) ||
        extractXMLAttribute(
          relationshipBlock,
          "spdx:relatedSpdxElement",
          "rdf:resource",
        );

      // Process dependency relationships
      if (
        relationshipType === "DEPENDS_ON" &&
        spdxElementId &&
        relatedSpdxElement
      ) {
        const fromPkg = packageMap.get(spdxElementId.replace(/^#/, ""));
        const toPkg = packageMap.get(relatedSpdxElement.replace(/^#/, ""));

        if (fromPkg && toPkg) {
          fromPkg.dependencies = fromPkg.dependencies || [];
          fromPkg.dependencies.push(toPkg.name);
        }
      } else if (
        relationshipType === "DEPENDENCY_OF" &&
        spdxElementId &&
        relatedSpdxElement
      ) {
        const fromPkg = packageMap.get(relatedSpdxElement.replace(/^#/, ""));
        const toPkg = packageMap.get(spdxElementId.replace(/^#/, ""));

        if (fromPkg && toPkg) {
          fromPkg.dependencies = fromPkg.dependencies || [];
          fromPkg.dependencies.push(toPkg.name);
        }
      }
    }
  }
}
