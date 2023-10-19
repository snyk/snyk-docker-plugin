import { fullImageSavePath } from "../../lib/image-save-path";

describe("image-save-path", () => {
  const TMP_FOLDER_REGEX =
    /.*[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/g;
  const CUSTOM_FOLDER_REGEX =
    /custom\/image\/path\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/g;

  test("when there is no custom image save path using system tmp folder", () => {
    const imageSavePath = undefined;

    const generatedImagePath = fullImageSavePath(imageSavePath);

    expect(generatedImagePath).toMatch(TMP_FOLDER_REGEX);
  });

  test("when there is custom image save path using custom folder", () => {
    const imageSavePath = "./custom/image/path";

    const generatedImagePath = fullImageSavePath(imageSavePath);

    expect(generatedImagePath).toMatch(CUSTOM_FOLDER_REGEX);
  });
});
