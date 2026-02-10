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

// array[*] indicates to truncate each element to the indicated size 
const RESPONSE_SIZE_LIMITS = {
  'containerConfig.data.user': { type: 'string', limit: 1024 },
  'containerConfig.data.exposedPorts': { type: 'array', limit: 500 },
  'containerConfig.data.exposedPorts[*]': { type: 'string', limit: 64 },
  'containerConfig.data.env': { type: 'array', limit: 500 },
  'containerConfig.data.env[*]': { type: 'string', limit: 1024 },
  'containerConfig.data.entrypoint': { type: 'array', limit: 500 },
  'containerConfig.data.entrypoint[*]': { type: 'string', limit: 1024 },
  'containerConfig.data.cmd': { type: 'array', limit: 500 },
  'containerConfig.data.cmd[*]': { type: 'string', limit: 1024 },
  'containerConfig.data.volumes': { type: 'array', limit: 500 },
  'containerConfig.data.volumes[*]': { type: 'string', limit: 1024 },
  'containerConfig.data.workingDir': { type: 'string', limit: 1024 },
  'containerConfig.data.stopSignal': { type: 'string', limit: 128 },
  'history.data': { type: 'array', limit: 1000 },
  'history.data[*].author': { type: 'string', limit: 128 },
  'history.data[*].createdBy': { type: 'string', limit: 128 },
  'history.data[*].comment': { type: 'string', limit: 4096 },
} as const;

export function truncateAdditionalFacts(facts: any[]): any[] {
  return facts.map(fact => {
    if (!fact || !fact.type || !fact.data) return fact;
    
    const truncatedData = truncateDataValue(fact.data, fact.type, 'data');
    return { ...fact, data: truncatedData };
  });
}

function truncateDataValue(value: any, factType: string, path: string): any {
  const limitKey = `${factType}.${path}`;
  const limitConfig = RESPONSE_SIZE_LIMITS[limitKey];
  
  // directly truncate if there's a match
  if (limitConfig) {
    value = truncateValue(value, limitConfig, limitKey);
  }
  
  if (Array.isArray(value)) {
    return value.map((item, index) => {
      // truncate individual array elements if they have limits
      const arrayElementLimitKey = `${factType}.${path}[*]`;
      const arrayElementLimit = RESPONSE_SIZE_LIMITS[arrayElementLimitKey];
      
      if (arrayElementLimit) {
        item = truncateValue(item, arrayElementLimit, `${arrayElementLimitKey}[${index}]`);
      }
      
      // if the elements are objects that we need to check fields, recurse on each object in the array
      // ie. recurse on each object within the History array fact. 
      if (typeof item === 'object' && item !== null) {
        const truncatedItem = { ...item };
        for (const [itemKey, itemValue] of Object.entries(item)) {
          truncatedItem[itemKey] = truncateDataValue(itemValue, factType, `${path}[*].${itemKey}`);
        }
        return truncatedItem;
      }
      return item;
    });
  } else if (typeof value === 'object' && value !== null) {
    const truncatedObject = { ...value };
    for (const [key, subValue] of Object.entries(value)) {
      truncatedObject[key] = truncateDataValue(subValue, factType, `${path}.${key}`);
    }
    return truncatedObject;
  }
  return value;
}

function truncateValue(value: any, limitConfig: any, fieldPath: string): any {
  switch (limitConfig.type) {
    case 'array':
      if (Array.isArray(value) && value.length > limitConfig.limit) {
        return value.slice(0, limitConfig.limit);
      }
      break;
    case 'string':
      if (typeof value === 'string' && value.length > limitConfig.limit) {
        return value.substring(0, limitConfig.limit);
      }
      break;
  }
  return value;
}
