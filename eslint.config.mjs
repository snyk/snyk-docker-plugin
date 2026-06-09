import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier/flat";

export default tseslint.config(
  {
    ignores: ["dist/", "node_modules/"],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  eslintConfigPrettier,
  {
    rules: {
      "no-shadow": "off",
      "@typescript-eslint/no-shadow": "off",
      "@typescript-eslint/naming-convention": "off",
      "no-bitwise": "off",
      "max-classes-per-file": "off",
      "no-console": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "no-case-declarations": "off",
      "no-useless-escape": "off",
      "no-prototype-builtins": "off",
      "@typescript-eslint/no-require-imports": "off",
      "@typescript-eslint/no-namespace": "off",
      "no-control-regex": "off",
      // New in ESLint v10 recommended — not part of the pre-migration rule set
      "preserve-caught-error": "off",
      "no-useless-assignment": "off",

      // New in typescript-eslint v8 recommended — not part of the pre-migration rule set
      "@typescript-eslint/no-empty-object-type": "off",
      "@typescript-eslint/no-unused-expressions": "off",

      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          // v8 changed the default from "none" to "all"; restore old behaviour
          caughtErrors: "none",
        },
      ],
    },
  },
);
