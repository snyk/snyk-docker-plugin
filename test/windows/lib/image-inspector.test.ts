import * as sinon from "sinon";
import { test } from "tap";

import * as plugin from "../../../lib";
import { Docker } from "../../../lib/docker";
import * as subProcess from "../../../lib/sub-process";

test("pull image from container registry plugin", async (t) => {
  const imageNameAndTag = "nginx:1.19.0";
  const dockerPullSpy = sinon.spy(Docker.prototype, "pull");
  const subprocessStub = sinon.stub(subProcess, "execute");
  subprocessStub.throws();

  await plugin.scan({
    path: imageNameAndTag,
  });

  t.teardown(() => {
    sinon.restore();
  });

  t.true(dockerPullSpy.called, "image pulled from remote registry");
});
