import type { ScanResult } from "./types";

export interface ScanPayloadMetrics {
  scanResultCount: number;
  applicationScanResultCount: number;
  scanResultPayloadBytes: number[];
  totalScanResultsPayloadBytes: number;
}

export function computeScanPayloadMetrics(
  scanResults: ScanResult[],
): ScanPayloadMetrics {
  const bytes = (v: unknown) =>
    Buffer.byteLength(JSON.stringify(v), "utf8");

  return {
    scanResultCount: scanResults.length,
    applicationScanResultCount: Math.max(0, scanResults.length - 1),
    scanResultPayloadBytes: scanResults.map(bytes),
    totalScanResultsPayloadBytes: bytes(scanResults),
  };
}
