// Stand-in for a build tool. Prints SNYK_* names (never values) and HTTP_PROXY.
process.stdout.write(
  JSON.stringify({
    snykKeys: Object.keys(process.env).filter((key) => /^snyk_/i.test(key)),
    HTTP_PROXY: process.env.HTTP_PROXY,
  }),
);
