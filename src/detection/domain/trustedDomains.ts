export interface TrustedDomain {
  readonly domain: string;
  readonly label: string;
}

export const BUILT_IN_TRUSTED_DOMAINS: readonly TrustedDomain[] = [
  { domain: 'microsoft.com', label: 'microsoft' },
  { domain: 'paypal.com', label: 'paypal' },
];
