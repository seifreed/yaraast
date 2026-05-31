const js = require("@eslint/js");
const tsParser = require("@typescript-eslint/parser");
const tsPlugin = require("@typescript-eslint/eslint-plugin");

module.exports = [
    {
        ignores: ["out/**", "dist/**", "**/*.d.ts"],
    },
    js.configs.recommended,
    {
        files: ["src/**/*.ts"],
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaVersion: 6,
                sourceType: "module",
            },
            globals: {
                Buffer: "readonly",
                NodeJS: "readonly",
                process: "readonly",
                setTimeout: "readonly",
            },
        },
        plugins: {
            "@typescript-eslint": tsPlugin,
        },
        rules: {
            "@typescript-eslint/naming-convention": "warn",
            curly: "warn",
            eqeqeq: "warn",
            "no-throw-literal": "warn",
        },
    },
];
