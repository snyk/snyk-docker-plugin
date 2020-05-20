import { detect as detectDynamically } from "./docker";
import { detect as detectHost } from "./host";
import { detect as detectStatically } from "./static";

export { detectDynamically, detectStatically, detectHost };
