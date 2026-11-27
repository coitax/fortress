// Redirect node:child_process to the test double before the SDK import binds it.
export async function resolve(specifier, context, nextResolve) {
  if (specifier === "node:child_process") {
    return {
      url: new URL("./fake_child_process.mjs", import.meta.url).href,
      shortCircuit: true,
    };
  }
  return nextResolve(specifier);
}
