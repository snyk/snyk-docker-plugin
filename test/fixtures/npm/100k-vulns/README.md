# 100K Vulnerability Path Test Container

This container is designed to test Snyk's 100k max vuln limit

## Structure

- **4,000 packages**
- **6 base dependencies** (each package depends on all 5):
  - `--hiljson`
  - `--legacy-peer-deps`
  - `--no-audit`
  - `-d3-ushape`
  - `-gzip-ize`
  - `-000webhost-admin`

## Build and Run

```bash
# Build the Docker image
docker build -t 100k-vulns .

# Run the container
docker run -p 3000:3000 100k-vulns
```

## Scan with Snyk

```bash
# Scan the container image
snyk container test 100k-vulns

# Monitor the container
snyk container monitor 100k-vulns
```




