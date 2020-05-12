import { test } from "tap";
import { getDockerArchivePath, getImageType } from "../../lib/image-type";
import { ImageType } from "../../lib/types";

test("getImageType() returns the expected transports", (t) => {
  t.plan(2);

  t.same(
    getImageType("nginx:latest"),
    ImageType.Identifier,
    "plain image identifier is handled",
  );
  t.same(
    getImageType("docker-archive:/tmp/nginx.tar"),
    ImageType.DockerArchive,
    "docker-archive is handled",
  );
});

test("getDockerArchivePath() returns the expected results", (t) => {
  t.plan(2);

  t.same(
    getDockerArchivePath("docker-archive:/tmp/nginx.tar"),
    "/tmp/nginx.tar",
    "returns extracted path",
  );
  t.same(
    getDockerArchivePath("bad-path"),
    "",
    "does not handle errors and returns empty path",
  );
});
