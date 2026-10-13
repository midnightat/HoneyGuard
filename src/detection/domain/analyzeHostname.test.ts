import { describe, expect, it } from 'vitest';
import sharedVectors from '../../../tools/domain-test-harness/cases.json';
import { analyzeHostname } from './analyzeHostname';
import { applyAsciiReplacements, hasSingleEditDistance } from './asciiLookalikes';
import {
  MAX_HOSTNAME_INPUT_LENGTH,
  normalizeHostname,
} from './normalizeHostname';
import { parseDomain } from './parseDomain';
import { classifySuspicion } from './riskPolicy';
import { toConfusableKey } from './unicodeConfusables';
import type { DomainAnalysisResult, DomainEvidenceMechanism, DomainFinding } from './types';

interface DomainVector {
  readonly id: string;
  readonly input: string;
  readonly expectedWhatwgHostname: string | null;
  readonly expected: {
    readonly status: DomainAnalysisResult['status'];
    readonly suspicion?: string;
    readonly normalizedHostname?: string;
    readonly registrableDomain?: string;
    readonly comparisonDomain?: string;
    readonly suffixType?: string;
    readonly reasonCode?: string;
    readonly findingKinds?: readonly string[];
  };
}

const vectors = sharedVectors as { readonly cases: readonly DomainVector[] };

function readWhatwgHostname(input: string): string | null {
  try {
    return new URL(`http://${input}/`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function findingKinds(result: DomainAnalysisResult): readonly string[] {
  return result.status === 'invalid' ? [] : result.findings.map(({ kind }) => kind).sort();
}

describe('analyzeHostname shared cases', () => {
  for (const testCase of vectors.cases) {
    it(testCase.id, () => {
      expect(readWhatwgHostname(testCase.input)).toBe(testCase.expectedWhatwgHostname);

      const result = analyzeHostname(testCase.input);
      expect(result.status).toBe(testCase.expected.status);

      if (result.status === 'success') {
        expect(result.suspicion).toBe(testCase.expected.suspicion);
        expect(result.normalizedHostname).toBe(testCase.expected.normalizedHostname);
        expect(result.registrableDomain).toBe(testCase.expected.registrableDomain);
        expect(result.comparisonDomain).toBe(testCase.expected.comparisonDomain ?? testCase.expected.registrableDomain);
        expect(result.suffixType).toBe(testCase.expected.suffixType);
      } else {
        expect('suspicion' in result).toBe(false);
        expect(result.reasonCode).toBe(testCase.expected.reasonCode);
      }

      expect(findingKinds(result)).toEqual([...(testCase.expected.findingKinds ?? [])].sort());
      expect(result.input).toBe(testCase.input);
      for (const finding of result.status === 'invalid' ? [] : result.findings) {
        expect(finding.id).toBeTruthy();
        expect(finding.evidenceGroupId).toBeTruthy();
        expect(finding.explanation).toBeTruthy();
      }
    });
  }
});

describe('hostname parsing and detection boundaries', () => {
  it.each([
    ['ASCII', 'a'.repeat(MAX_HOSTNAME_INPUT_LENGTH)],
    ['Unicode', 'ü'.repeat(MAX_HOSTNAME_INPUT_LENGTH)],
    ['supplementary Unicode', '😀'.repeat(MAX_HOSTNAME_INPUT_LENGTH / 2)],
  ])('allows the preliminary input limit for %s before canonical hostname validation', (_, input) => {
    expect(input).toHaveLength(MAX_HOSTNAME_INPUT_LENGTH);
    expect(analyzeHostname(input)).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });
  });

  it.each([
    ['ASCII', 'a'.repeat(MAX_HOSTNAME_INPUT_LENGTH + 1)],
    ['Unicode', 'ü'.repeat(MAX_HOSTNAME_INPUT_LENGTH + 1)],
    ['supplementary Unicode', '😀'.repeat(MAX_HOSTNAME_INPUT_LENGTH / 2 + 1)],
  ])('rejects over-limit %s input before hostname normalization', (_, input) => {
    expect(analyzeHostname(input)).toMatchObject({
      status: 'invalid',
      reasonCode: 'input_too_long',
    });
    expect(normalizeHostname(input)).toMatchObject({
      status: 'invalid',
      reasonCode: 'input_too_long',
    });
  });

  it('checks the input limit before parsing optional trusted domains', () => {
    expect(
      analyzeHostname('a'.repeat(MAX_HOSTNAME_INPUT_LENGTH + 1), {
        trustedDomains: ['not/a/hostname'],
      }),
    ).toMatchObject({
      status: 'invalid',
      reasonCode: 'input_too_long',
    });
  });

  it('normalizes case and one terminal dot', () => {
    expect(normalizeHostname('Microsoft.COM.')).toMatchObject({
      status: 'success',
      normalizedHostname: 'microsoft.com',
    });
  });

  it('rejects repeated terminal dots and empty labels', () => {
    expect(normalizeHostname('microsoft.com..')).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });
    expect(normalizeHostname('a..com')).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });
  });

  it('enforces 63-octet A-label and 253-character hostname limits after IDNA normalization', () => {
    const maxLengthLabel = 'a'.repeat(63);
    expect(normalizeHostname(`${maxLengthLabel}.com`)).toMatchObject({
      status: 'success',
    });
    expect(normalizeHostname(`${'a'.repeat(64)}.com`)).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });
    expect(analyzeHostname(`${'a'.repeat(64)}.com`)).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });

    const idnaLabelAtLimit = `${'ü'.repeat(57)}.com`;
    expect(new URL(`http://${idnaLabelAtLimit}/`).hostname.split('.')[0]).toHaveLength(63);
    expect(normalizeHostname(idnaLabelAtLimit)).toMatchObject({ status: 'success' });
    expect(normalizeHostname(`${'ü'.repeat(58)}.com`)).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });
    expect(analyzeHostname(`${'ü'.repeat(58)}.com`)).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });

    const hostnameAtLimit = [
      'a'.repeat(63),
      'b'.repeat(63),
      'c'.repeat(63),
      'd'.repeat(57),
      'com',
    ].join('.');
    expect(hostnameAtLimit).toHaveLength(253);
    expect(normalizeHostname(hostnameAtLimit)).toMatchObject({
      status: 'success',
      normalizedHostname: hostnameAtLimit,
    });
    expect(normalizeHostname(`${hostnameAtLimit}.`)).toMatchObject({
      status: 'success',
      normalizedHostname: hostnameAtLimit,
    });

    const hostnameOverLimit = [
      'a'.repeat(63),
      'b'.repeat(63),
      'c'.repeat(63),
      'd'.repeat(58),
      'com',
    ].join('.');
    expect(hostnameOverLimit).toHaveLength(254);
    expect(normalizeHostname(hostnameOverLimit)).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });
    expect(analyzeHostname(hostnameOverLimit)).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_hostname',
    });
  });

  it('keeps multiple algorithms for a single confusable as one evidence group', () => {
    const result = analyzeHostname('microsоft.com');
    expect(result.status).toBe('success');
    if (result.status !== 'success') return;

    expect(result.suspicion).toBe('medium');
    expect(new Set(result.findings.map(({ evidenceGroupId }) => evidenceGroupId)).size).toBe(1);
    expect(result.findings.map(({ kind }) => kind).sort()).toEqual([
      'mixed_script',
      'unicode_confusable',
    ]);
  });

  it('retains partial brand evidence for unknown suffixes without assigning suspicion', () => {
    const result = analyzeHostname('rnicrosoft.unknownxyz');
    expect(result.status).toBe('unsupported');
    if (result.status !== 'unsupported') return;

    expect(result.reasonCode).toBe('unknown_suffix');
    expect(result.findings.map(({ kind }) => kind)).toContain('ascii_replacement');
    expect('suspicion' in result).toBe(false);
  });

  it('uses user reference domains without suppressing built-in reference checks', () => {
    const result = analyzeHostname('c0ntoso.com', { trustedDomains: ['contoso.com'] });
    expect(result.status).toBe('success');
    if (result.status === 'success') {
      expect(result.suspicion).toBe('medium');
      expect(result.findings[0]?.matchedDomain).toBe('contoso.com');
    }

    expect(analyzeHostname('microsoft.com', { trustedDomains: ['not a domain'] })).toMatchObject({
      status: 'invalid',
      reasonCode: 'invalid_trusted_domain',
    });
  });

  it('does not classify a close spelling as high or confirmed phishing', () => {
    const result = analyzeHostname('microsofts.com');
    expect(result.status).toBe('success');
    if (result.status === 'success') {
      expect(result.suspicion).toBe('low');
      expect(result.findings.every(({ strength }) => strength === 'weak')).toBe(true);
    }
  });

  it('preserves complete multi-code-point official mappings', () => {
    expect(toConfusableKey('\u0149')).toBe("'n");
    expect(Array.from(toConfusableKey('\u0149'))).toHaveLength(2);
  });

  it('applies only documented ASCII substitutions and bounded edit distance', () => {
    expect(applyAsciiReplacements('rnicrosoft')?.candidate).toBe('microsoft');
    expect(applyAsciiReplacements('paypa1')?.candidate).toBe('paypal');
    expect(hasSingleEditDistance('microsoft', 'microsofts')).toBe(true);
    expect(hasSingleEditDistance('microsoft', 'microsofthosting')).toBe(false);
  });

  it('distinguishes ICANN, PRIVATE, and special-use boundaries', () => {
    expect(parseDomain('login.example.co.uk')).toMatchObject({
      suffixType: 'icann',
      registrableDomain: 'example.co.uk',
      publicSuffix: 'co.uk',
    });
    expect(parseDomain('tenant.github.io')).toMatchObject({
      suffixType: 'private',
      registrableDomain: 'tenant.github.io',
      publicSuffix: 'github.io',
    });
    expect(parseDomain('microsoft.com.evil.test')).toMatchObject({
      suffixType: 'special-use',
      registrableDomain: null,
      comparisonDomain: 'evil.test',
      subdomain: 'microsoft.com',
    });
  });

  it('keeps the result contract discriminated', () => {
    const results: readonly DomainAnalysisResult[] = [
      analyzeHostname(''),
      analyzeHostname('127.0.0.1'),
      analyzeHostname('microsoft.com'),
    ];
    expect(results.map(({ status }) => status)).toEqual(['invalid', 'unsupported', 'success']);
    expect(classifySuspicion([])).toBe('none');
  });
});

describe('risk policy evidence de-duplication', () => {
  const finding = (
    id: string,
    evidenceGroupId: string,
    strength: DomainFinding['strength'],
    mechanism: DomainEvidenceMechanism,
    kind: DomainFinding['kind'],
  ): DomainFinding => ({
    id,
    evidenceGroupId,
    mechanism,
    kind,
    strength,
    explanation: 'Test evidence.',
  });

  it('uses the strongest finding once per evidence group', () => {
    expect(
      classifySuspicion([
        finding('replacement', 'same-spoof', 'strong', 'brand-label-lookalike', 'ascii_replacement'),
        finding('unicode', 'same-spoof', 'strong', 'brand-label-lookalike', 'unicode_confusable'),
        finding('edit-distance', 'same-spoof', 'weak', 'brand-label-lookalike', 'edit_distance'),
      ]),
    ).toBe('medium');
  });

  it('does not escalate multiple brands found by the same mechanism', () => {
    expect(
      classifySuspicion([
        finding(
          'paypal-subdomain',
          'paypal-in-subdomain',
          'strong',
          'brand-in-subdomain',
          'brand_in_subdomain',
        ),
        finding(
          'microsoft-subdomain',
          'microsoft-in-subdomain',
          'strong',
          'brand-in-subdomain',
          'brand_in_subdomain',
        ),
      ]),
    ).toBe('medium');
  });

  it('requires independent strong mechanisms for high', () => {
    expect(
      classifySuspicion([
        finding(
          'brand-label-mimic',
          'brand-label:1:paypal.com',
          'strong',
          'brand-label-lookalike',
          'ascii_replacement',
        ),
        finding(
          'brand-in-subdomain',
          'brand-subdomain:paypal.com:0',
          'strong',
          'brand-in-subdomain',
          'brand_in_subdomain',
        ),
      ]),
    ).toBe('high');
  });
});
