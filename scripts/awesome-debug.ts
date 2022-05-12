import * as minimist from "minimist";
import { scan } from "../lib";

setImmediate(async () => {
  const { _, ...args } = minimist(process.argv.slice(2));
  const image = _[0];
  if (_.length > 1) {
    console.log("too many parameters, please specify image name only once");
    process.exit(1);
  }

  const pluginResult = await scan({
    path: image,
    ...args,
  });
  console.log(JSON.stringify(pluginResult.scanResults, undefined, 2));
  process.exit(0);
});
