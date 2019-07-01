import { Docker } from "../docker";

export { analyze };

const HASH_PKGPATHS = ["**/node"];

export { HASH_PKGPATHS };

async function analyze(docker: Docker) {
  const result = docker.getActionProducts("hash");
  return {
    Image: docker.getTargetImage(),
    AnalyzeType: "Hash",
    Analysis: Object.keys(result).map((i) => {
      return {
        name: i,
        hash: result[i],
      };
    }),
  };
}
