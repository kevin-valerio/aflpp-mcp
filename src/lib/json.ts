export function stableJsonStringify(value: unknown): string {
  return JSON.stringify(value, (_k, v) => v, 0);
}

