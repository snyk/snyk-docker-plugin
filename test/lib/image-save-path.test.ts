import { test } from "tap";

import { fullImageSavePath } from "../../lib/image-save-path";

test("generate image save path", (c) => {
  c.test("when there is no custom image save path", (t) => {
    const imageSavePath = undefined;

    const generatedImagePath = fullImageSavePath(imageSavePath);

    t.ok(
      generatedImagePath.match(
        /.*[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/g,
      ),
      "path created using system tmp folder",
    );
    t.done();
  });

  c.test("when there is custom image save path", (t) => {
    const imageSavePath = "./custom/image/path";

    const generatedImagePath = fullImageSavePath(imageSavePath);

    t.ok(
      generatedImagePath.match(
        /custom\/image\/path\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/g,
      ),
      "path created using custom folder",
    );
    t.done();
  });
  c.done();
});
