/**
 * Stabilize PluginResponse.analytics in snapshots.
 *
 * `containerPluginTimings.data` holds wall-clock durations (e.g. nodeAnalysisMs)
 * that are non-deterministic, but the KEY names are an analytics contract we want
 * pinned. So we snapshot a timings object with its keys intact and every value
 * blanked to "<ms>". Everything else in analytics (e.g. containerScanPayloadMetrics)
 * is deterministic — PLUGIN_VERSION is "0.0.0-local" — and is snapshotted in full.
 *
 * The timings fact is recognized by its `name` ("containerPluginTimings"), not by
 * value types alone — a value-type-only predicate would also match other all-number
 * objects in the response (payload byte counts, hashes, coordinates) and silently
 * blank them. We additionally require `data`'s values to all be numbers: after
 * blanking they become "<ms>" strings, so the predicate no longer matches the copy
 * we re-print — this is the recursion guard.
 *
 * Plain JS so it loads before ts-jest (needed for the Windows Jest config).
 */
expect.addSnapshotSerializer({
  test(val) {
    if (
      val === null ||
      typeof val !== "object" ||
      val.name !== "containerPluginTimings" ||
      val.data === null ||
      typeof val.data !== "object"
    ) {
      return false;
    }
    const timings = Object.values(val.data);
    return timings.length > 0 && timings.every((v) => typeof v === "number");
  },
  serialize(val, config, indentation, depth, refs, printer) {
    const blanked = { ...val, data: {} };
    for (const key of Object.keys(val.data)) {
      blanked.data[key] = "<ms>";
    }
    return printer(blanked, config, indentation, depth, refs);
  },
});
