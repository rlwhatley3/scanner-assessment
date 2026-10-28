import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { concurrently } from "concurrently";

const uiDir = fileURLToPath(new URL(".", import.meta.url));
const serverDir = resolve(uiDir, "..", "server");
const basePath =
  process.env.VITE_CODER_APP_BASE_PATH ||
  process.env.VITE_CODE_SERVER_BASE_PATH ||
  process.env.VITE_APP_BASE_PATH ||
  "/";

const { result } = concurrently(
  [
    {
      command: "vite",
      name: "UI",
      cwd: uiDir,
      env: { VITE_APP_BASE_PATH: basePath },
    },
    {
      command:
        'cargo watch --watch src --watch Cargo.toml --watch ../engine/src --watch ../engine/rule_sets --watch ../engine/Cargo.toml --exec "run --locked"',
      name: "API",
      cwd: serverDir,
    },
  ],
  {
    killOthersOn: ["failure", "success"],
    prefix: "name",
    prefixColors: ["cyan", "green"],
  },
);

result.catch(() => {
  process.exitCode = 1;
});
