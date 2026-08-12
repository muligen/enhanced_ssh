import { cp, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const sourceDirectory = fileURLToPath(
  new URL("../src/test-ui/public/", import.meta.url),
);
const destinationDirectory = fileURLToPath(
  new URL("../dist/src/test-ui/public/", import.meta.url),
);

await mkdir(destinationDirectory, { recursive: true });

for (const fileName of ["index.html", "styles.css", "app.js"]) {
  await cp(
    `${sourceDirectory}/${fileName}`,
    `${destinationDirectory}/${fileName}`,
  );
}
