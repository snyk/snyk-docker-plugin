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
}
