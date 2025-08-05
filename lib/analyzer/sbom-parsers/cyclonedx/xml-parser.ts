import { SBOMDocument } from "../types";
import {
  extractXMLAttribute,
  extractXMLBlocks,
  extractXMLValue,
  isXMLContent,
  validateRequiredFields,
} from "../xml-utils";
import {
  BaseCycloneDXParser,
  CycloneDXComponent,
  CycloneDXDependency,
} from "./base-parser";

/**
 * CycloneDX XML format parser
 */
export class CycloneDXXMLParser extends BaseCycloneDXParser {
  constructor() {
    super("xml");
  }

  public canParse(content: string): boolean {
    if (!isXMLContent(content)) {
      return false;
    }

    return (
      content.includes("cyclonedx") ||
      content.includes("CycloneDX") ||
      content.includes("http://cyclonedx.org") ||
      content.includes("bomFormat")
    );
  }

  public parse(content: string): SBOMDocument | null {
    try {
      // Extract document metadata
      const bomFormat =
        extractXMLValue(content, ["bom:bomFormat", "bomFormat"]) || "CycloneDX";
      const specVersion =
        extractXMLValue(content, ["bom:specVersion", "specVersion"]) || "";

      if (bomFormat !== "CycloneDX" || !specVersion) {
        this.debug("Invalid CycloneDX XML document");
        return null;
      }

      const serialNumber = extractXMLValue(content, [
        "bom:serialNumber",
        "serialNumber",
      ]);
      // const version = extractXMLValue(content, ["bom:version", "version"]) || "1";

      // Extract metadata
      const metadata = this.extractMetadata(content);

      // Extract components (excluding metadata component)
      const components = this.extractComponents(content);

      // Convert components to SBOM packages
      const packages = components.map((comp) =>
        this.convertToSBOMPackage(comp),
      );

      // Process dependencies
      const dependencies = this.extractDependencies(content);
      if (dependencies.length > 0) {
        const componentMap = this.createComponentMap(components, packages);
        this.processDependencies(dependencies, packages, componentMap);
      }

      // Build document name
      const documentName =
        metadata.component?.name || serialNumber || "CycloneDX XML Document";
      const documentVersion = `CycloneDX-${specVersion}`;

      return this.buildSBOMDocument(
        documentName,
        documentVersion,
        serialNumber || undefined,
        metadata,
        packages,
      );
    } catch (error) {
      return this.handleError(error, "XML");
    }
  }

  private extractMetadata(content: string) {
    const metadataBlocks = extractXMLBlocks(content, [
      "bom:metadata",
      "metadata",
    ]);

    if (metadataBlocks.length === 0) {
      return {};
    }

    const metadataBlock = metadataBlocks[0];

    // Extract timestamp
    const timestamp = extractXMLValue(metadataBlock, [
      "bom:timestamp",
      "timestamp",
    ]);

    // Extract tools
    const tools: any[] = [];
    const toolBlocks = extractXMLBlocks(metadataBlock, ["bom:tool", "tool"]);

    toolBlocks.forEach((toolBlock) => {
      const vendor = extractXMLValue(toolBlock, ["bom:vendor", "vendor"]);
      const name = extractXMLValue(toolBlock, ["bom:name", "name"]);
      const version = extractXMLValue(toolBlock, ["bom:version", "version"]);

      if (name) {
        tools.push({ vendor, name, version });
      }
    });

    // Extract authors
    const authors: any[] = [];
    const authorBlocks = extractXMLBlocks(metadataBlock, [
      "bom:author",
      "author",
    ]);

    authorBlocks.forEach((authorBlock) => {
      const name = extractXMLValue(authorBlock, ["bom:name", "name"]);
      const email = extractXMLValue(authorBlock, ["bom:email", "email"]);

      if (name) {
        authors.push({ name, email });
      }
    });

    // Extract metadata component
    const componentBlocks = extractXMLBlocks(metadataBlock, [
      "bom:component",
      "component",
    ]);
    let component: CycloneDXComponent | undefined;

    if (componentBlocks.length > 0) {
      component = this.parseXMLComponent(componentBlocks[0]) || undefined;
    }

    return {
      timestamp: timestamp || undefined,
      tools: tools.length > 0 ? tools : undefined,
      authors: authors.length > 0 ? authors : undefined,
      component,
    };
  }

  private extractComponents(content: string): CycloneDXComponent[] {
    const components: CycloneDXComponent[] = [];

    // Find components sections (not metadata component)
    const componentsBlocks = extractXMLBlocks(content, [
      "bom:components",
      "components",
    ]);

    componentsBlocks.forEach((componentsBlock) => {
      const componentBlocks = extractXMLBlocks(componentsBlock, [
        "bom:component",
        "component",
      ]);

      componentBlocks.forEach((componentBlock) => {
        const component = this.parseXMLComponent(componentBlock);
        if (component) {
          components.push(component);
        }
      });
    });

    return components;
  }

  private parseXMLComponent(componentBlock: string): CycloneDXComponent | null {
    const name = extractXMLValue(componentBlock, ["bom:name", "name"]);

    if (!validateRequiredFields({ name }, ["name"])) {
      return null;
    }

    const type =
      extractXMLAttribute(componentBlock, "component", "type") ||
      extractXMLAttribute(componentBlock, "bom:component", "type") ||
      "library";

    const bomRef =
      extractXMLAttribute(componentBlock, "component", "bom-ref") ||
      extractXMLAttribute(componentBlock, "bom:component", "bom-ref");

    const version =
      extractXMLValue(componentBlock, ["bom:version", "version"]) || "unknown";
    const group = extractXMLValue(componentBlock, ["bom:group", "group"]);
    const description = extractXMLValue(componentBlock, [
      "bom:description",
      "description",
    ]);
    const scope = extractXMLValue(componentBlock, ["bom:scope", "scope"]);
    const copyright = extractXMLValue(componentBlock, [
      "bom:copyright",
      "copyright",
    ]);
    const purl = extractXMLValue(componentBlock, ["bom:purl", "purl"]);
    const cpe = extractXMLValue(componentBlock, ["bom:cpe", "cpe"]);

    // Extract license information
    const licenses: any[] = [];
    const licenseBlocks = extractXMLBlocks(componentBlock, [
      "bom:license",
      "license",
    ]);

    licenseBlocks.forEach((licenseBlock) => {
      const licenseId = extractXMLValue(licenseBlock, ["bom:id", "id"]);
      const licenseName = extractXMLValue(licenseBlock, ["bom:name", "name"]);
      const licenseUrl = extractXMLValue(licenseBlock, ["bom:url", "url"]);
      const expression = extractXMLValue(licenseBlock, [
        "bom:expression",
        "expression",
      ]);

      if (expression) {
        licenses.push({ expression });
      } else if (licenseId || licenseName) {
        licenses.push({
          license: {
            id: licenseId,
            name: licenseName,
            url: licenseUrl,
          },
        });
      }
    });

    // Extract hashes
    const hashes: any[] = [];
    const hashBlocks = extractXMLBlocks(componentBlock, ["bom:hash", "hash"]);

    hashBlocks.forEach((hashBlock) => {
      const alg =
        extractXMLAttribute(hashBlock, "hash", "alg") ||
        extractXMLAttribute(hashBlock, "bom:hash", "alg");
      const content =
        extractXMLValue(hashBlock, ["bom:content", "content"]) ||
        hashBlock.replace(/<[^>]*>/g, "").trim();

      if (alg && content) {
        hashes.push({ alg, content });
      }
    });

    // Extract supplier information
    let supplier: any;
    const supplierBlock = extractXMLBlocks(componentBlock, [
      "bom:supplier",
      "supplier",
    ])[0];
    if (supplierBlock) {
      const supplierName = extractXMLValue(supplierBlock, ["bom:name", "name"]);
      if (supplierName) {
        supplier = { name: supplierName };
      }
    }

    const author = extractXMLValue(componentBlock, ["bom:author", "author"]);
    const publisher = extractXMLValue(componentBlock, [
      "bom:publisher",
      "publisher",
    ]);

    // Extract external references
    const externalReferences: any[] = [];
    const extRefsBlocks = extractXMLBlocks(componentBlock, [
      "bom:externalReferences",
      "externalReferences",
    ]);

    extRefsBlocks.forEach((extRefsBlock) => {
      const referenceBlocks = extractXMLBlocks(extRefsBlock, [
        "bom:reference",
        "reference",
      ]);

      referenceBlocks.forEach((refBlock) => {
        const refType =
          extractXMLAttribute(refBlock, "reference", "type") ||
          extractXMLAttribute(refBlock, "bom:reference", "type");
        const url = extractXMLValue(refBlock, ["bom:url", "url"]);
        const comment = extractXMLValue(refBlock, ["bom:comment", "comment"]);

        if (refType && url) {
          externalReferences.push({ type: refType, url, comment });
        }
      });
    });

    return {
      type,
      "bom-ref": bomRef || undefined,
      name: name!,
      version,
      group: group || undefined,
      description: description || undefined,
      scope: scope || undefined,
      supplier,
      author: author || undefined,
      publisher: publisher || undefined,
      licenses: licenses.length > 0 ? licenses : undefined,
      hashes: hashes.length > 0 ? hashes : undefined,
      copyright: copyright || undefined,
      purl: purl || undefined,
      cpe: cpe || undefined,
      externalReferences:
        externalReferences.length > 0 ? externalReferences : undefined,
    };
  }

  private extractDependencies(content: string): CycloneDXDependency[] {
    const dependencies: CycloneDXDependency[] = [];

    const dependenciesBlocks = extractXMLBlocks(content, [
      "bom:dependencies",
      "dependencies",
    ]);

    dependenciesBlocks.forEach((dependenciesBlock) => {
      const dependencyBlocks = extractXMLBlocks(dependenciesBlock, [
        "bom:dependency",
        "dependency",
      ]);

      dependencyBlocks.forEach((dependencyBlock) => {
        const ref =
          extractXMLAttribute(dependencyBlock, "dependency", "ref") ||
          extractXMLAttribute(dependencyBlock, "bom:dependency", "ref");

        if (ref) {
          const dependsOn: string[] = [];

          // Look for nested dependency elements (CycloneDX XML format)
          const nestedDependencyBlocks = extractXMLBlocks(dependencyBlock, [
            "bom:dependency",
            "dependency",
          ]);

          nestedDependencyBlocks.forEach((nestedDepBlock) => {
            const nestedRef =
              extractXMLAttribute(nestedDepBlock, "dependency", "ref") ||
              extractXMLAttribute(nestedDepBlock, "bom:dependency", "ref");
            if (nestedRef) {
              dependsOn.push(nestedRef);
            }
          });

          // Also check for dependsOn blocks (other CycloneDX formats)
          const dependsOnBlocks = extractXMLBlocks(dependencyBlock, [
            "bom:dependsOn",
            "dependsOn",
          ]);

          dependsOnBlocks.forEach((dependsOnBlock) => {
            const dependsOnRef =
              extractXMLAttribute(dependsOnBlock, "dependsOn", "ref") ||
              extractXMLAttribute(dependsOnBlock, "bom:dependsOn", "ref");
            if (dependsOnRef) {
              dependsOn.push(dependsOnRef);
            }
          });

          dependencies.push({
            ref,
            dependsOn: dependsOn.length > 0 ? dependsOn : undefined,
          });
        }
      });
    });

    return dependencies;
  }
}
