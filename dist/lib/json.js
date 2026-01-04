export function stableJsonStringify(value) {
    return JSON.stringify(value, (_k, v) => v, 0);
}
