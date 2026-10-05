/**
 * Canonical bytes: a restricted profile of RFC 8785 (JSON Canonicalization Scheme).
 *
 * Allowed values: null, booleans, safe integers, strings (well-formed UTF-16), arrays, and plain
 * objects. Floats, NaN, Infinity, unsafe integers, undefined, functions, and lone surrogates are
 * rejected so that every implementation produces the same bytes without number formatting rules.
 * Object keys are sorted by UTF-16 code unit order, as RFC 8785 requires.
 */
import { ProtocolError, utf8 } from './bytes';

export type Canonical = null | boolean | number | string | Canonical[] | { [key: string]: Canonical };

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function serialize(value: unknown, depth: number): string {
  if (depth > 32) throw new ProtocolError('canonical: nesting too deep');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new ProtocolError('canonical: only safe integers are allowed');
      return Object.is(value, -0) ? '0' : String(value);
    case 'string':
      if (LONE_SURROGATE.test(value)) throw new ProtocolError('canonical: lone surrogate in string');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return '[' + value.map((v) => serialize(v, depth + 1)).join(',') + ']';
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new ProtocolError('canonical: only plain objects are allowed');
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const parts: string[] = [];
      for (const k of keys) {
        const v = obj[k];
        if (v === undefined) throw new ProtocolError(`canonical: undefined value for key ${JSON.stringify(k)}`);
        if (LONE_SURROGATE.test(k)) throw new ProtocolError('canonical: lone surrogate in key');
        parts.push(JSON.stringify(k) + ':' + serialize(v, depth + 1));
      }
      return '{' + parts.join(',') + '}';
    }
    default:
      throw new ProtocolError(`canonical: unsupported type ${typeof value}`);
  }
}

export function canonicalString(value: unknown): string {
  return serialize(value, 0);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return utf8(serialize(value, 0));
}

/** Signing input with domain separation: context || 0x00 || canonical(value). */
export function signingInput(context: string, value: unknown): Uint8Array {
  const ctx = utf8(context);
  const body = canonicalBytes(value);
  const out = new Uint8Array(ctx.length + 1 + body.length);
  out.set(ctx, 0);
  out[ctx.length] = 0;
  out.set(body, ctx.length + 1);
  return out;
}
