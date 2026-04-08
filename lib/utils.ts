import { PluginWarningsFact } from "./facts";

// array[*] indicates to truncate each element to the indicated size
export const RESPONSE_SIZE_LIMITS = {
  "containerConfig.data.user": { type: "string", limit: 1024 },
  "containerConfig.data.exposedPorts": { type: "array", limit: 500 },
  "containerConfig.data.exposedPorts[*]": { type: "string", limit: 64 },
  "containerConfig.data.env": { type: "array", limit: 500 },
  "containerConfig.data.env[*]": { type: "string", limit: 1024 },
  "containerConfig.data.entrypoint": { type: "array", limit: 500 },
  "containerConfig.data.entrypoint[*]": { type: "string", limit: 1024 },
  "containerConfig.data.cmd": { type: "array", limit: 500 },
  "containerConfig.data.cmd[*]": { type: "string", limit: 1024 },
  "containerConfig.data.volumes": { type: "array", limit: 500 },
  "containerConfig.data.volumes[*]": { type: "string", limit: 1024 },
  "containerConfig.data.workingDir": { type: "string", limit: 1024 },
  "containerConfig.data.stopSignal": { type: "string", limit: 128 },
  "history.data": { type: "array", limit: 1000 },
  "history.data[*].author": { type: "string", limit: 128 },
  "history.data[*].createdBy": { type: "string", limit: 4096 },
  "history.data[*].comment": { type: "string", limit: 4096 },
} as const;

interface TruncationInfo {
  type: "array" | "string";
  countAboveLimit: number;
}

export function truncateAdditionalFacts(facts: any[]): any[] {
  const truncationTracker: Record<string, TruncationInfo> = {};

  const processedFacts = facts.map((fact) => {
    if (!fact || !fact.type || !fact.data) {
      return fact;
    }
    if (fact.type === "depGraph") {
      return fact;
    }

    const truncatedData = truncateDataValue(
      fact.data,
      fact.type,
      "data",
      truncationTracker,
    );
    return { ...fact, data: truncatedData };
  });

  if (Object.keys(truncationTracker).length > 0) {
    const existingWarnings = processedFacts.find(
      (f) => f.type === "pluginWarnings",
    ) as PluginWarningsFact | undefined;

    if (existingWarnings) {
      existingWarnings.data.truncatedFacts = truncationTracker;
    } else {
      const pluginWarningsFact: PluginWarningsFact = {
        type: "pluginWarnings",
        data: {
          truncatedFacts: truncationTracker,
        },
      };
      processedFacts.push(pluginWarningsFact);
    }
  }

  return processedFacts;
}

function hasAnyLimitsForPath(factType: string, path: string): boolean {
  const prefix = `${factType}.${path}`;
  return Object.keys(RESPONSE_SIZE_LIMITS).some((limitKey) =>
    limitKey.startsWith(prefix),
  );
}

function truncateDataValue(
  value: any,
  factType: string,
  path: string,
  truncationTracker: Record<string, TruncationInfo>,
): any {
  const limitKey = `${factType}.${path}`;
  const limitConfig = RESPONSE_SIZE_LIMITS[limitKey];

  // directly truncate if there's a match
  if (limitConfig) {
    value = truncateValue(value, limitConfig, limitKey, truncationTracker);
  }

  if (!hasAnyLimitsForPath(factType, path)) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => {
      return truncateDataValue(item, factType, `${path}[*]`, truncationTracker);
    });
  } else if (typeof value === "object" && value !== null) {
    const truncatedObject: any = {};

    for (const [key, subValue] of Object.entries(value)) {
      truncatedObject[key] = truncateDataValue(
        subValue,
        factType,
        `${path}.${key}`,
        truncationTracker,
      );
    }
    return truncatedObject;
  }
  return value;
}

function truncateValue(
  value: any,
  limitConfig: any,
  fieldPath: string,
  truncationTracker: Record<string, TruncationInfo>,
): any {
  switch (limitConfig.type) {
    case "array":
      if (Array.isArray(value) && value.length > limitConfig.limit) {
        const truncatedCount = value.length - limitConfig.limit;
        // report how many elements were truncated
        truncationTracker[fieldPath] = {
          type: "array",
          countAboveLimit: truncatedCount,
        };
        return value.slice(0, limitConfig.limit);
      }
      break;
    case "string":
      if (typeof value === "string" && value.length > limitConfig.limit) {
        const truncatedCount = value.length - limitConfig.limit;
        // report the maximum number of characters that were truncated for this field
        const existing = truncationTracker[fieldPath];
        if (!existing || truncatedCount > existing.countAboveLimit) {
          truncationTracker[fieldPath] = {
            type: "string",
            countAboveLimit: truncatedCount,
          };
        }
        return value.substring(0, limitConfig.limit);
      }
      break;
  }
  return value;
}
