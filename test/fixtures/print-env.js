// Stand-in for a tool the plugin spawns. Prints variable names and the values
// of test-owned variables only, so no real secret value can reach CI logs.
const env = process.env;
process.stdout.write(
  JSON.stringify({
    keys: Object.keys(env),
    HTTP_PROXY: env.HTTP_PROXY,
    http_proxy: env.http_proxy,
    UNRELATED_VAR: env.UNRELATED_VAR,
  }),
);
