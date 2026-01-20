FROM debian:bookworm-slim

# Install packages via apt
RUN apt-get update && apt-get install -y curl wget && rm -rf /var/lib/apt/lists/*

# Create properly formatted SPDX file for curl (conflicts with apt)
RUN mkdir -p /docker/sbom/curl && \
    echo '{ \
  "spdxVersion": "SPDX-2.3", \
  "dataLicense": "CC0-1.0", \
  "SPDXID": "SPDXRef-dhi-curl", \
  "name": "SPDX document for dhi/curl 7.88.0", \
  "documentNamespace": "dhi-curl-7.88.0", \
  "creationInfo": { \
    "creators": ["Organization: Test", "Tool: manual"], \
    "created": "2024-01-01T00:00:00Z" \
  }, \
  "packages": [ \
    { \
      "name": "dhi/curl", \
      "SPDXID": "SPDXRef-dhi-curl", \
      "versionInfo": "7.88.0", \
      "supplier": "Organization: Test", \
      "downloadLocation": "NOASSERTION", \
      "filesAnalyzed": false, \
      "licenseConcluded": "NOASSERTION", \
      "licenseDeclared": "NOASSERTION", \
      "externalRefs": [ \
        { \
          "referenceCategory": "PACKAGE-MANAGER", \
          "referenceType": "purl", \
          "referenceLocator": "pkg:dhi/curl@7.88.0" \
        } \
      ], \
      "primaryPackagePurpose": "CONTAINER" \
    } \
  ] \
}' > /docker/sbom/curl/spdx.curl.json

# Create properly formatted SPDX file for redis-server (no conflict)
RUN mkdir -p /docker/sbom/redis && \
    echo '{ \
  "spdxVersion": "SPDX-2.3", \
  "dataLicense": "CC0-1.0", \
  "SPDXID": "SPDXRef-dhi-redis", \
  "name": "SPDX document for dhi/redis-server 7.0.15", \
  "documentNamespace": "dhi-redis-server-7.0.15", \
  "creationInfo": { \
    "creators": ["Organization: Test", "Tool: manual"], \
    "created": "2024-01-01T00:00:00Z" \
  }, \
  "packages": [ \
    { \
      "name": "dhi/redis-server", \
      "SPDXID": "SPDXRef-dhi-redis-server", \
      "versionInfo": "7.0.15", \
      "supplier": "Organization: Test", \
      "downloadLocation": "NOASSERTION", \
      "filesAnalyzed": false, \
      "licenseConcluded": "NOASSERTION", \
      "licenseDeclared": "NOASSERTION", \
      "externalRefs": [ \
        { \
          "referenceCategory": "PACKAGE-MANAGER", \
          "referenceType": "purl", \
          "referenceLocator": "pkg:dhi/redis-server@7.0.15" \
        } \
      ], \
      "primaryPackagePurpose": "CONTAINER" \
    } \
  ] \
}' > /docker/sbom/redis/spdx.redis-server.json