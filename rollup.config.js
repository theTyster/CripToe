import typescript from "@rollup/plugin-typescript";
import dts from "rollup-plugin-dts";
import { nodeResolve } from "@rollup/plugin-node-resolve";

const config = [
  {
    input: ".build/transpiled/index.js",
    output: {
      file: "dist/CripToe.js",
      format: "es",
      sourcemap: true,
    },
    plugins: [typescript(), nodeResolve()],
  },
  {
    input: ".build/transpiled/index.d.ts",
    output: {
      file: "dist/CripToe.ts",
      format: "es",
    },
    plugins: [dts(), nodeResolve()],
  },
];

export default config;
