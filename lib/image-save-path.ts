import * as crypto from "crypto";
import * as os from "os";
import * as path from "path";

export function fullImageSavePath(imageSavePath: string | undefined): string {
  let imagePath = os.tmpdir();
  if (imageSavePath) {
    imagePath = path.normalize(imageSavePath);
  }

  return path.join(imagePath, crypto.randomUUID());
}
