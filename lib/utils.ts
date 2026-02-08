import { ContainerConfig, HistoryEntry } from "./extractor/types";

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

const SIZE_LIMITS = {
  CONTAINER_CONFIG: {
    EXPOSED_PORTS: 500,
    ENV: 500,
    ENTRYPOINT: 500,
    CMD: 500,
    VOLUMES: 500,
  },
  HISTORY: 1000,
} as const;

export function validateSizeConstraintsContainerConfig(
  config?: ContainerConfig,
): ContainerConfig | undefined {
  if (!config) {
    return config;
  }

  const result = { ...config };
  const { CONTAINER_CONFIG } = SIZE_LIMITS;

  if (result.ExposedPorts) {
    const exposedPortsKeys = Object.keys(result.ExposedPorts);
    if (exposedPortsKeys.length > CONTAINER_CONFIG.EXPOSED_PORTS) {
      console.warn(
        `Container config exposedPorts truncated from ${exposedPortsKeys.length} to ${CONTAINER_CONFIG.EXPOSED_PORTS} items`,
      );
      const truncatedPorts: { [port: string]: object } = {};
      exposedPortsKeys
        .slice(0, CONTAINER_CONFIG.EXPOSED_PORTS)
        .forEach((port) => {
          truncatedPorts[port] = result.ExposedPorts![port];
        });
      result.ExposedPorts = truncatedPorts;
    }
  }
  if (result.Env && result.Env.length > CONTAINER_CONFIG.ENV) {
    console.warn(
      `Container config env truncated from ${result.Env.length} to ${CONTAINER_CONFIG.ENV} items`,
    );
    result.Env = result.Env.slice(0, CONTAINER_CONFIG.ENV);
  }

  if (
    result.Entrypoint &&
    result.Entrypoint.length > CONTAINER_CONFIG.ENTRYPOINT
  ) {
    console.warn(
      `Container config entrypoint truncated from ${result.Entrypoint.length} to ${CONTAINER_CONFIG.ENTRYPOINT} items`,
    );
    result.Entrypoint = result.Entrypoint.slice(0, CONTAINER_CONFIG.ENTRYPOINT);
  }

  if (result.Cmd && result.Cmd.length > CONTAINER_CONFIG.CMD) {
    console.warn(
      `Container config cmd truncated from ${result.Cmd.length} to ${CONTAINER_CONFIG.CMD} items`,
    );
    result.Cmd = result.Cmd.slice(0, CONTAINER_CONFIG.CMD);
  }
  if (result.Volumes) {
    const volumeKeys = Object.keys(result.Volumes);
    if (volumeKeys.length > CONTAINER_CONFIG.VOLUMES) {
      console.warn(
        `Container config volumes truncated from ${volumeKeys.length} to ${CONTAINER_CONFIG.VOLUMES} items`,
      );
      const truncatedVolumes: { [path: string]: object } = {};
      volumeKeys.slice(0, CONTAINER_CONFIG.VOLUMES).forEach((volume) => {
        truncatedVolumes[volume] = result.Volumes![volume];
      });
      result.Volumes = truncatedVolumes;
    }
  }

  return result;
}

export function validateSizeConstraintsHistory(
  history?: HistoryEntry[],
): HistoryEntry[] | undefined {
  if (!history) {
    return history;
  }

  if (history.length > SIZE_LIMITS.HISTORY) {
    console.warn(
      `History array truncated from ${history.length} to ${SIZE_LIMITS.HISTORY} items`,
    );
    return history.slice(0, SIZE_LIMITS.HISTORY);
  }

  return history;
}
