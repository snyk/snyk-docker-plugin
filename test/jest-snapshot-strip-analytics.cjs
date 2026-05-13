/**
 * Strip PluginResponse.analytics from snapshot output (timings are non-deterministic).
 * Plain JS so it loads before ts-jest (needed for Windows Jest config).
 */
expect.addSnapshotSerializer({
  test(val) {
    return (
      val !== null &&
      typeof val === "object" &&
      Array.isArray(val.scanResults) &&
      Object.prototype.hasOwnProperty.call(val, "analytics")
    );
  },
  serialize(val, config, indentation, depth, refs, printer) {
    const { analytics: _a, ...rest } = val;
    return printer(rest, config, indentation, depth, refs);
  },
});
