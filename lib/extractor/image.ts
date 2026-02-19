import { parseImageReference } from "../image-reference";
import { PluginOptions } from "../types";

export { ImageName, ImageDigest, getImageNames };
class ImageName {
  public name: string;
  public tag?: string;
  public digests: Record<string, ImageDigest>;

  constructor(
    targetImage: string,
    digests: { manifest?: string; index?: string } = {},
  ) {
    const parsed = parseImageReference(targetImage);
    this.name = parsed.registry ? parsed.registry + "/" + parsed.repository : parsed.repository;

    // If the image name has a tag, use it. If the image name has
    // nether a tag nor a digest, use "latest".
    this.tag = parsed.tag || parsed.digest ? parsed.tag : "latest";

    this.digests = {};
    if (digests.index) {
      this.digests.index = new ImageDigest(digests.index);
    }
    if (digests.manifest) {
      this.digests.manifest = new ImageDigest(digests.manifest);
    }

    // If the image name has a digest, and it's not the same as the manifest or index digest, add it as the unknown digest.
    if (parsed.digest && !this.digests.manifest?.equals(parsed.digest) && !this.digests.index?.equals(parsed.digest)) {
        this.digests.unknown = new ImageDigest(parsed.digest);
    }
  }

  public getAllNames(): string[] {
    const names: string[] = [];
    if (this.tag) {
      names.push(this.name + ":" + this.tag);
    }
    if (this.digests.manifest) {
      names.push(this.name + "@" + this.digests.manifest.toString());
    }
    if (this.digests.index) {
      names.push(this.name + "@" + this.digests.index.toString());
    }
    if (this.digests.unknown) {
      names.push(this.name + "@" + this.digests.unknown.toString());
    }
    return names;
  }
}

const ALGORITHM = {
  sha256: 64,
  sha384: 96,
  sha512: 128,
};

class ImageDigest {
  public alg: string;
  public hex: string;

  constructor(digest: string) {
    // this function matches the implementation
    // https://github.com/opencontainers/go-digest/blob/b0b31a459546bae38a6c9676e9c5f35861e58894/digest.go#L103
    const i = digest.indexOf(":");
    if (i <= 0 || i + 1 === digest.length) {
      throw new Error("invalid digest format");
    }

    const alg = digest.slice(0, i);
    this.hex = digest.slice(i + 1);

    // make sure the algorithm is valid, and that we get the same
    // amount of hex characters as we expect for the given algorithm.
    this.alg = alg;
    if (this.alg === undefined || !Object.keys(ALGORITHM).includes(this.alg)) {
      throw new Error(`unsupported digest algorithm: ${alg}`);
    }
    if (this.hex.length !== ALGORITHM[this.alg]) {
      throw new Error(
        `digest algorithm ${this.alg} suggested length ${
          ALGORITHM[this.alg]
        }, but got digest with length ${this.hex.length}`,
      );
    }
    if (!new RegExp(`^[a-f0-9]{${ALGORITHM[this.alg]}}`).test(this.hex)) {
      throw new Error(`digest contains invalid characters`);
    }
  }

  public toString(): string {
    return this.alg + ":" + this.hex;
  }

  public equals(other: ImageDigest | string): boolean {
    if (typeof other === "string") {
      return this.toString() === other;
    }
    return this.alg === other.alg && this.hex === other.hex;
  }
}

function getImageNames(
  options?: Partial<PluginOptions>,
  imageName?: ImageName,
): string[] {
  if (imageName) {
    return imageName.getAllNames();
  }

  const names: string[] = [];
  if (options?.imageNameAndTag) {
    const imageName = new ImageName(options.imageNameAndTag);
    names.push(...imageName.getAllNames());
  }

  if (
    options?.imageNameAndDigest &&
    options?.imageNameAndDigest !== options?.imageNameAndTag
  ) {
    const imageName = new ImageName(options.imageNameAndDigest);
    names.push(...imageName.getAllNames());
  }

  return names;
}
