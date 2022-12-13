export { ImageName, ImageDigest };
class ImageName {
  public name: string;
  public tag?: string;
  public digests: Record<string, ImageDigest>;

  constructor(
    targetImage: string,
    digests: { manifest?: string; index?: string } = {},
  ) {
    // this regex has been copied from
    // https://github.com/distribution/distribution/blob/fb2188868d771aa27e5781a32bf78d4c113c18a6/reference/regexp.go#L101
    // (code has been modified to print the regex), and then adjusted to
    // Javascript. The required modifications were replacing `[:xdigit:]` with
    // `[a-fA-F0-9]` and escaping the slashes.
    // Note that the digest matched in this Regex will match digests that have
    // uppercase-letters, while the regex used in validateDigest does NOT match
    // uppercase-letters. This simply matches the behaviour from the upstream
    // `reference` and `go-digest `packages.
    //
    // we're matching pattern: <registry:port_number>(optional)/<image_name>(mandatory):<image_tag>(optional)@<tag_identifier>(optional)
    // This Regex contains three capture groups:
    // 1) The repository / image name
    // 2) tag
    // 3) digest
    const re =
      /^((?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?\/)?[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:\/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?)(?::([\w][\w.-]{0,127}))?(?:@([A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][A-Fa-f0-9]{32,}))?$/gi;

    const groups = re.exec(targetImage);
    if (groups === null) {
      if (targetImage === "") {
        throw new Error("image name is empty");
      }
      if (re.exec(targetImage.toLowerCase()) !== null) {
        throw new Error("image repository contains uppercase letter");
      }
      throw new Error("invalid image reference format");
    }

    const parsedGroups = {
      name: groups[1],
      tag: groups[2],
      digest: groups[3],
    };

    this.name = parsedGroups.name;

    const NameTotalLengthMax = 255;
    if (this.name.length > NameTotalLengthMax) {
      throw new Error("image repository name is more than 255 characters");
    }

    this.tag =
      parsedGroups.tag || parsedGroups.digest ? parsedGroups.tag : "latest";

    this.digests = {};
    if (digests.index) {
      this.digests.index = new ImageDigest(digests.index);
    }
    if (digests.manifest) {
      this.digests.manifest = new ImageDigest(digests.manifest);
    }

    if (parsedGroups.digest) {
      const digest = new ImageDigest(parsedGroups.digest);
      if (this.digests.manifest !== digest && this.digests.index !== digest) {
        this.digests.unknown = digest;
      }
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
}
