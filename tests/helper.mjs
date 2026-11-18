export const results = [];
export function test(name, fn) {
  try { fn(); results.push({ name }); }
  catch (error) { results.push({ name, error }); }
}
