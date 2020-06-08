import { test } from "tap";
import { getArchivePath, getImageType } from "../../lib/image-type";
import { ImageType } from "../../lib/types";

test("getImageType() returns the expected transports", (t) => {
  t.plan(3);

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
  t.same(
    getImageType("oci-archive:/tmp/nginx.tar"),
    ImageType.OciArchive,
    "oci-archive is handled",
  );
});

test("getArchivePath() returns the expected results", (t) => {
  t.plan(3);

  t.same(
    getArchivePath("docker-archive:/tmp/nginx.tar"),
    "/tmp/nginx.tar",
    "returns extracted path from docker-archive target image",
  );

  t.same(
    getArchivePath("oci-archive:/tmp/nginx.tar"),
    "/tmp/nginx.tar",
    "returns extracted path from oci-archive target image",
  );

  t.throws(
    () => getArchivePath("bad-path"),
    'The provided archive path is missing image specific prefix, eg."docker-archive:" or "oci-archive:"',
    "throws expected error when provided bad path",
  );
});
