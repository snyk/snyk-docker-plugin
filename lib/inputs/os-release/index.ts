import { getOsRelease as getOsReleaseDynamic } from "./docker";
import { getOsRelease as getOsReleaseHost } from "./host";
import { getOsRelease as getOsReleaseStatic } from "./static";

export { getOsReleaseDynamic, getOsReleaseStatic, getOsReleaseHost };
