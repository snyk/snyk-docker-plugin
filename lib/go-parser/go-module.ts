export class GoModule {
  public name: string;
  public version: string;
  public packages: string[] = [];

  constructor(name: string, version: string) {
    this.name = name;
    this.version = version;
  }

  // fullName returns the module's name and version, separated with an `@`. This
  // reflects how Go stores them on disk (except for vendored paths).
  public fullName(): string {
    return this.name + "@" + this.version;
  }

  public snykNormalisedVersion(): string {
    // Versions in Go have leading 'v'
    let version = this.version.substring(1);
    // In versions with hash, we only care about hash
    // v0.0.0-20200905004654-be1d3432aa8f => #be1d3432aa8f
    version = version.includes("-")
      ? `#${version.substring(version.lastIndexOf("-") + 1)}`
      : version;

    return version;
  }
}
