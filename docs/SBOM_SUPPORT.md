# SBOM Support in Snyk Docker Plugin

This document describes the Software Bill of Materials (SBOM) scanning functionality added to the Snyk Docker Plugin.

## Overview

The Snyk Docker Plugin now supports scanning and processing SBOM files found within container images. This feature allows you to:

- **Discover SBOM files** automatically within container layers
- **Parse multiple SBOM formats** (SPDX JSON/XML/RDF/YAML, CycloneDX JSON/XML, and more)
- **Merge SBOM data** with filesystem-detected dependencies using configurable strategies
- **Validate consistency** between SBOM declarations and actual filesystem contents

## Supported SBOM Formats

### Currently Supported
- **SPDX JSON** (`.spdx.json`, `.spdx`) - Complete SPDX JSON specification support
- **SPDX XML** (`.spdx.xml`) - Full namespace support with regex-based parsing
- **SPDX RDF** (`.spdx.rdf`) - RDF/XML format with full RDF resource handling
- **SPDX YAML** (`.spdx.yaml`, `.spdx.yml`) - Structured YAML parsing with indentation handling
- **CycloneDX JSON** (`.cyclonedx.json`, `bom.json`) - Complete CycloneDX JSON support
- **CycloneDX XML** (`.cyclonedx.xml`) - Full feature support with shared XML utilities

### Future Enhancements
- SPDX Tag-Value format
- Additional CycloneDX features

## CLI Usage

### Basic SBOM Scanning

```bash
# Scan with SBOM files ignored (default behavior)
snyk container test my-image

# Explicitly disable SBOM scanning entirely (skip file detection)
snyk container test my-image --exclude-sbom
```

### SBOM Merge Strategies

Control how SBOM data is combined with filesystem analysis:

```bash
# Ignore SBOM data completely (default)
snyk container test my-image --sbom-merge-strategy=ignore

# Supplement filesystem analysis with SBOM data
snyk container test my-image --sbom-merge-strategy=supplement

# Override filesystem data with SBOM data when conflicts exist
snyk container test my-image --sbom-merge-strategy=override

# Validate SBOM against filesystem analysis and report discrepancies
snyk container test my-image --sbom-merge-strategy=validate
```

### Conflict Resolution

When the same package exists in both SBOM and filesystem with different versions:

```bash
# Prioritize filesystem detection (default)
snyk container test my-image --sbom-precedence=filesystem

# Prioritize SBOM declarations
snyk container test my-image --sbom-precedence=sbom
```

### Strict Validation Mode

```bash
# Fail the scan if SBOM validation finds discrepancies
snyk container test my-image --sbom-merge-strategy=validate --sbom-validation-strict
```

## Merge Strategies Explained

### 1. Ignore Strategy (Default)
- **Behavior**: Completely ignores SBOM data, using only filesystem analysis
- **Use Case**: Standard container scanning without SBOM influence
- **Conflict Handling**: No conflicts as SBOM data is not processed

```bash
# Example: Filesystem has curl@7.64.0, SBOM has curl@7.68.0
# Result: Only filesystem curl@7.64.0 is included
snyk container test my-image --sbom-merge-strategy=ignore
```

### 2. Supplement Strategy
- **Behavior**: Adds SBOM packages that don't exist in filesystem analysis
- **Use Case**: Enhance filesystem detection with additional SBOM information
- **Conflict Handling**: Keeps both versions if package names match but versions differ

```bash
# Example: Filesystem has curl@7.64.0, SBOM has curl@7.68.0
# Result: Both versions are included in the analysis
snyk container test my-image --sbom-merge-strategy=supplement
```

### 3. Override Strategy
- **Behavior**: Replaces filesystem packages with SBOM versions when conflicts exist
- **Use Case**: Trust SBOM as authoritative source of truth
- **Conflict Handling**: Uses `--sbom-precedence` to decide which version to keep

```bash
# Prioritize SBOM versions over filesystem detection
snyk container test my-image --sbom-merge-strategy=override --sbom-precedence=sbom
```

### 4. Validate Strategy
- **Behavior**: Compares SBOM and filesystem analysis, reports discrepancies
- **Use Case**: Audit SBOM accuracy and completeness
- **Conflict Handling**: Reports all differences without modifying results

```bash
# Generate validation report
snyk container test my-image --sbom-merge-strategy=validate
```

## SBOM File Detection

The plugin automatically detects SBOM files in common locations:

### File Patterns
- `*.spdx`, `*.spdx.json`, `*.spdx.xml`, `*.spdx.rdf`, `*.spdx.yaml`, `*.spdx.yml`
- `*.cyclonedx.json`, `*.cyclonedx.xml`
- `*sbom.json`, `*sbom.xml`
- `*bom.json`, `*bom.xml`

### Format-Specific Features

#### XML Parsing (SPDX XML, SPDX RDF, CycloneDX XML)
- **Dependency-free**: Uses regex-based parsing without external XML libraries
- **Namespace support**: Handles both namespaced and non-namespaced elements
- **Full metadata extraction**: Packages, licenses, PURLs, checksums, relationships
- **Dependency mapping**: Processes relationships and dependency structures
- **Shared utilities**: Consolidated XML parsing logic for consistent behavior

#### RDF Processing (SPDX RDF)
- **RDF resource handling**: Properly processes RDF triples and resource references
- **SPDX ontology support**: Understands SPDX RDF vocabulary and relationships
- **Multi-format RDF**: Supports various RDF serializations within XML

#### YAML Processing (SPDX YAML)
- **Indentation-aware**: Handles YAML structural indentation correctly
- **Multi-document support**: Processes YAML document separators
- **Flexible property mapping**: Maps various YAML property naming conventions
- **List processing**: Correctly handles YAML arrays and sequences

### Common Locations
- `/opt/sbom/`
- `/usr/share/sbom/`
- `/etc/sbom/`
- `/.sbom/`
- `/var/lib/dpkg/info/` (for distroless images)

## Integration Examples

### Example 1: Standard Container Scanning (Default)

```bash
# Scan image ignoring any SBOM files (default behavior)
snyk container test node:16-alpine

# Output will include:
# - Only packages detected from filesystem analysis
# - SBOM files are detected but their contents are ignored
```

### Example 2: Enhanced Scanning with SBOM

```bash
# Scan image with SBOM supplementation
snyk container test node:16-alpine --sbom-merge-strategy=supplement

# Output will include:
# - All packages detected from filesystem analysis
# - Additional packages found only in SBOM files
# - Both versions if same package exists with different versions
```

### Example 3: SBOM Validation Workflow

```bash
# Validate SBOM accuracy in CI/CD
snyk container test my-app:latest --sbom-merge-strategy=validate --sbom-validation-strict

# Exit codes:
# 0 = SBOM matches filesystem analysis
# 1 = Validation discrepancies found (when --sbom-validation-strict is used)
```

### Example 4: SBOM-First Analysis

```bash
# Trust SBOM over filesystem detection
snyk container test my-image --sbom-merge-strategy=override --sbom-precedence=sbom

# Use case: When SBOM is known to be more accurate than filesystem scanning
```

## Output Format

SBOM data is included in the standard Snyk output with additional metadata:

```json
{
  "facts": [
    {
      "type": "sbomMergeResult",
      "data": {
        "sbomPackagesAdded": 15,
        "conflictsResolved": 3,
        "validationIssues": [
          "Version mismatch for curl: filesystem has 7.64.0, SBOM has 7.68.0"
        ]
      }
    }
  ]
}
```

### Package Metadata

Packages sourced from SBOM include additional metadata:

```json
{
  "name": "curl",
  "version": "7.68.0",
  "source": "sbom",
  "_sbomSource": {
    "filePath": "/opt/sbom/app.spdx.json",
    "sbomName": "Application SBOM",
    "license": "MIT",
    "supplier": "curl team",
    "checksums": {
      "sha256": "abc123..."
    }
  }
}
```

## Best Practices

### 1. Start with Ignore Strategy (Default)
- The default `--sbom-merge-strategy=ignore` provides standard filesystem-based scanning
- SBOM files are detected but not used in analysis, ensuring consistent behavior

### 2. Explore SBOM Enhancement
- Use `--sbom-merge-strategy=supplement` to see what additional information SBOM provides
- Review the enhanced dependency list for completeness

### 3. Validate SBOM Quality
- Use `--sbom-merge-strategy=validate` to audit SBOM accuracy
- Address discrepancies in your SBOM generation process

### 4. Choose Appropriate Precedence
- Use `--sbom-precedence=filesystem` when filesystem scanning is reliable
- Use `--sbom-precedence=sbom` when SBOM is authoritative (e.g., for distroless images)

### 5. CI/CD Integration
- Add SBOM validation to your container security pipeline
- Use `--sbom-validation-strict` to enforce SBOM quality gates

## Troubleshooting

### Common Issues

1. **No SBOM files detected**
   - Verify SBOM files exist in expected locations
   - Check file naming follows supported patterns
   - Ensure SBOM files are in supported formats

2. **Parsing errors**
   - Validate SBOM file syntax using SPDX/CycloneDX validators
   - Check for required fields in SBOM documents

3. **Unexpected merge results**
   - Review package version differences between SBOM and filesystem
   - Consider using `validate` strategy first to understand discrepancies

### Debug Output

Enable debug logging to see SBOM processing details:

```bash
DEBUG=snyk:sbom* snyk container test my-image
```

## Limitations

- XML format support is planned but not yet implemented
- SBOM relationship parsing is basic (dependency relationships)
- Performance impact may be noticeable with very large SBOM files
- Only package information is extracted (not file-level details)

## Contributing

To contribute to SBOM support:

1. **Adding new formats**: Implement parsers in `lib/analyzer/sbom-parsers/`
2. **Improving detection**: Update patterns in `lib/inputs/sbom/static.ts`
3. **Enhancing merge logic**: Modify strategies in `lib/analyzer/sbom/merger.ts`

See the test files in `test/lib/analyzer/sbom/` for examples and test patterns.