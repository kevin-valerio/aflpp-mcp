import path from "node:path";
import { ToolError } from "./errors.js";
export function requireObject(value, name) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new ToolError("INVALID_ARGUMENT", `${name} must be an object`);
    }
    return value;
}
export function requireString(value, name) {
    if (typeof value !== "string")
        throw new ToolError("INVALID_ARGUMENT", `${name} must be a string`);
    return value;
}
export function requireOptionalString(value, name) {
    if (value === undefined)
        return undefined;
    return requireString(value, name);
}
export function requireStringArray(value, name) {
    if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
        throw new ToolError("INVALID_ARGUMENT", `${name} must be an array of strings`);
    }
    return value;
}
export function requireOptionalNumber(value, name) {
    if (value === undefined)
        return undefined;
    if (typeof value !== "number" || Number.isNaN(value)) {
        throw new ToolError("INVALID_ARGUMENT", `${name} must be a number`);
    }
    return value;
}
export function requireOptionalBoolean(value, name) {
    if (value === undefined)
        return undefined;
    if (typeof value !== "boolean")
        throw new ToolError("INVALID_ARGUMENT", `${name} must be a boolean`);
    return value;
}
export function validateName(value, fieldName) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value)) {
        throw new ToolError("INVALID_ARGUMENT", `${fieldName} must match /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/`);
    }
    if (value === "." || value === "..") {
        throw new ToolError("INVALID_ARGUMENT", `${fieldName} cannot be '.' or '..'`);
    }
    return value;
}
export function assertWithinRoot(root, candidatePath, name) {
    const rootAbs = path.resolve(root);
    const candAbs = path.resolve(candidatePath);
    const rel = path.relative(rootAbs, candAbs);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
        throw new ToolError("PATH_OUTSIDE_ROOT", `${name} must be within workspace root`);
    }
    return candAbs;
}
