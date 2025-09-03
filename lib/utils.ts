/**
 * Validates a Docker image reference format using the official Docker reference regex.
 * @param imageReference The Docker image reference to validate
 * @returns true if valid, false if invalid
 */
export function isValidDockerImageReference(imageReference: string): boolean {
  // Docker image reference validation regex from the official Docker packages:
  // https://github.com/distribution/reference/blob/ff14fafe2236e51c2894ac07d4bdfc778e96d682/regexp.go#L9
  // Original regex: ^((?:(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*|\[(?:[a-fA-F0-9:]+)\])(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*)(?::([\w][\w.-]{0,127}))?(?:@([A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][[:xdigit:]]{32,}))?$
  // Note: Converted [[:xdigit:]] to [a-fA-F0-9] and escaped the forward slashes for JavaScript compatibility.
  const dockerImageRegex =
    /^((?:(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*|\[(?:[a-fA-F0-9:]+)\])(?::[0-9]+)?\/)?[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*)(?::([\w][\w.-]{0,127}))?(?:@([A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][a-fA-F0-9]{32,}))?$/;

  return dockerImageRegex.test(imageReference);
}
