import { parse } from 'tldts';
import type { SuffixType } from './types';

export interface DomainParts {
  readonly suffixType: SuffixType;
  readonly registrableDomain: string | null;
  readonly comparisonDomain: string | null;
  readonly subdomain: string | null;
  readonly publicSuffix: string | null;
}

export function parseDomain(hostname: string): DomainParts {
  const result = parse(hostname, {
    allowPrivateDomains: true,
    detectSpecialUse: true,
  });

  const suffixType: SuffixType = result.isSpecialUse
    ? 'special-use'
    : result.isPrivate
      ? 'private'
      : result.isIcann
        ? 'icann'
        : 'unknown';

  const comparisonDomain = result.domain?.toLowerCase() ?? null;
  return {
    suffixType,
    registrableDomain:
      suffixType === 'icann' || suffixType === 'private' ? comparisonDomain : null,
    comparisonDomain,
    subdomain: result.subdomain?.toLowerCase() ?? null,
    publicSuffix: result.publicSuffix?.toLowerCase() ?? null,
  };
}
