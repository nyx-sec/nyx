import { foo } from "./foo";
import { baz } from "../bar/baz";
import { util } from "@scope/util";
import { x } from "@/lib/x";
import { promises as fs } from "node:fs/promises";

export function main() {
  return foo() + baz() + util() + x();
}
