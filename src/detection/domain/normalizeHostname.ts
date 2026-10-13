import { decode, encode } from 'punycode/';
import type { DomainReasonCode } from './types';

export const MAX_HOSTNAME_INPUT_LENGTH = 1024;
export const HOSTNAME_INPUT_TOO_LONG_EXPLANATION =
  `Ввод слишком длинный: допустимо не более ${MAX_HOSTNAME_INPUT_LENGTH} кодовых единиц UTF-16 до IDNA-нормализации.`;

export type HostnameNormalization =
  | {
      readonly status: 'success';
      readonly normalizedHostname: string;
      readonly unicodeHostname: string;
    }
  | {
      readonly status: 'invalid';
      readonly reasonCode: Extract<
        DomainReasonCode,
        | 'empty_input'
        | 'input_too_long'
        | 'not_hostname'
        | 'invalid_hostname'
        | 'invalid_idna'
      >;
    }
  | {
      readonly status: 'unsupported';
      readonly reasonCode: Extract<DomainReasonCode, 'ip_literal' | 'local_hostname'>;
      readonly normalizedHostname: string;
    };

const IDNA_DOT_SEPARATORS = /[\u3002\uff0e\uff61]/gu;
const HOSTNAME_CHARACTERS = /^[\p{L}\p{M}\p{N}.-]+$/u;
const IPV4_ADDRESS = /^\d{1,3}(?:\.\d{1,3}){3}$/u;

function isPunycodeLabel(label: string): boolean {
  return label.startsWith('xn--');
}

function decodeHostname(normalizedHostname: string): string | null {
  const unicodeLabels: string[] = [];

  for (const label of normalizedHostname.split('.')) {
    if (!isPunycodeLabel(label)) {
      unicodeLabels.push(label);
      continue;
    }

    try {
      const payload = label.slice(4);
      const decodedLabel = decode(payload);
      if (encode(decodedLabel).toLowerCase() !== payload) return null;

      const roundTripLabel = new URL(`http://${decodedLabel}/`).hostname.toLowerCase();
      if (roundTripLabel !== label) return null;
      unicodeLabels.push(decodedLabel);
    } catch {
      return null;
    }
  }

  return unicodeLabels.join('.');
}

export function normalizeHostname(input: string): HostnameNormalization {
  if (input.length === 0) {
    return { status: 'invalid', reasonCode: 'empty_input' };
  }

  if (input.length > MAX_HOSTNAME_INPUT_LENGTH) {
    return { status: 'invalid', reasonCode: 'input_too_long' };
  }

  if (input.trim().length === 0) {
    return { status: 'invalid', reasonCode: 'empty_input' };
  }

  if (input.startsWith('[') || input.endsWith(']')) {
    try {
      const parsedIp = new URL(`http://${input}/`);
      if (parsedIp.hostname.startsWith('[')) {
        return {
          status: 'unsupported',
          reasonCode: 'ip_literal',
          normalizedHostname: parsedIp.hostname.toLowerCase(),
        };
      }
    } catch {
      return { status: 'invalid', reasonCode: 'invalid_hostname' };
    }
    return { status: 'invalid', reasonCode: 'not_hostname' };
  }

  if (input !== input.trim() || /[\s/@?#\\:]/u.test(input)) {
    return { status: 'invalid', reasonCode: 'not_hostname' };
  }

  const mappedInput = input.replace(IDNA_DOT_SEPARATORS, '.');
  if (mappedInput.endsWith('..')) {
    return { status: 'invalid', reasonCode: 'invalid_hostname' };
  }
  const candidate = mappedInput.replace(/\.$/u, '');
  if (!candidate || candidate.startsWith('.') || candidate.includes('..') || !HOSTNAME_CHARACTERS.test(candidate)) {
    return { status: 'invalid', reasonCode: 'invalid_hostname' };
  }

  let normalizedHostname: string;
  try {
    normalizedHostname = new URL(`http://${candidate}/`).hostname.toLowerCase().replace(/\.$/u, '');
  } catch {
    return { status: 'invalid', reasonCode: 'invalid_hostname' };
  }

  const asciiLabels = normalizedHostname.split('.');
  if (normalizedHostname.length > 253 || asciiLabels.some((label) => label.length > 63)) {
    return { status: 'invalid', reasonCode: 'invalid_hostname' };
  }

  if (!normalizedHostname || normalizedHostname.startsWith('[') || IPV4_ADDRESS.test(normalizedHostname)) {
    return {
      status: 'unsupported',
      reasonCode: 'ip_literal',
      normalizedHostname,
    };
  }

  if (normalizedHostname === 'localhost' || normalizedHostname.endsWith('.localhost')) {
    return {
      status: 'unsupported',
      reasonCode: 'local_hostname',
      normalizedHostname,
    };
  }

  const unicodeHostname = decodeHostname(normalizedHostname);
  if (unicodeHostname === null) {
    return { status: 'invalid', reasonCode: 'invalid_idna' };
  }

  return {
    status: 'success',
    normalizedHostname,
    unicodeHostname,
  };
}
