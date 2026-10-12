import {
  applyAsciiReplacements,
  hasSingleEditDistance,
} from './asciiLookalikes';
import { normalizeHostname } from './normalizeHostname';
import { parseDomain } from './parseDomain';
import { classifySuspicion } from './riskPolicy';
import { BUILT_IN_TRUSTED_DOMAINS, type TrustedDomain } from './trustedDomains';
import {
  containsUnsupportedScript,
  toConfusableKey,
  UNICODE_CONFUSABLES_VERSION,
} from './unicodeConfusables';
import type {
  AnalyzeHostnameOptions,
  DomainAnalysisResult,
  DomainFinding,
} from './types';

const SUPPORTED_SPECIAL_USE_SUFFIXES = new Set(['test']);

interface CandidateLabel {
  readonly label: string;
  readonly index: number;
}

function makeFinding(
  findings: Map<string, DomainFinding>,
  finding: DomainFinding,
): void {
  findings.set(finding.id, finding);
}

function parseTrustedDomains(
  trustedDomains: readonly string[] | undefined,
): readonly TrustedDomain[] {
  if (trustedDomains === undefined) return [];
  const parsed: TrustedDomain[] = [];

  for (const input of trustedDomains) {
    const normalized = normalizeHostname(input);
    if (normalized.status !== 'success') {
      throw new TypeError('Each trusted domain must be a supported hostname.');
    }

    const parts = parseDomain(normalized.normalizedHostname);
    if (!parts.registrableDomain || parts.registrableDomain !== normalized.normalizedHostname) {
      throw new TypeError('Each trusted domain must be a registrable domain without subdomains.');
    }

    parsed.push({
      domain: parts.registrableDomain,
      label: normalized.unicodeHostname.split('.')[0],
    });
  }
  return parsed;
}

function getComparisonLabels(hostname: string, comparisonDomain: string | null): readonly CandidateLabel[] {
  const labels = hostname.split('.');
  const comparisonLabelCount = comparisonDomain?.split('.').length ?? 0;
  const startIndex = comparisonDomain ? labels.length - comparisonLabelCount : 0;

  return labels
    .slice(startIndex)
    .map((label, offset) => ({ label, index: startIndex + offset }));
}

function collectFindings(
  normalizedHostname: string,
  unicodeHostname: string,
  comparisonDomain: string | null,
  subdomain: string | null,
  references: readonly TrustedDomain[],
): readonly DomainFinding[] {
  const findings = new Map<string, DomainFinding>();
  const normalizedLabels = getComparisonLabels(normalizedHostname, comparisonDomain);
  const unicodeLabels = getComparisonLabels(unicodeHostname, comparisonDomain);

  for (const [index, label] of unicodeHostname.split('.').entries()) {
    const scriptKinds = new Set(
      [...label].flatMap((character) => {
        if (/\p{Script=Latin}/u.test(character)) return ['Latin'];
        if (/\p{Script=Cyrillic}/u.test(character)) return ['Cyrillic'];
        if (/\p{Script=Greek}/u.test(character)) return ['Greek'];
        return [];
      }),
    );
    if (scriptKinds.size > 1) {
      const confusableReference = /[^\x00-\x7f]/u.test(label)
        ? references.find((reference) => toConfusableKey(label.toLowerCase()) === toConfusableKey(reference.label))
        : undefined;
      const evidenceGroupId = confusableReference
        ? `brand-label:${index}:${confusableReference.domain}`
        : `mixed-script:${index}`;
      makeFinding(findings, {
        id: `mixed-script:${index}${confusableReference ? `:${confusableReference.domain}` : ''}`,
        evidenceGroupId,
        mechanism: 'mixed-script',
        kind: 'mixed_script',
        strength: 'weak',
        ...(confusableReference ? { matchedDomain: confusableReference.domain } : {}),
        explanation: 'В одной метке смешаны Latin, Cyrillic или Greek символы; это может встречаться и в легитимных IDN.',
      });
    }
  }

  for (const candidate of normalizedLabels) {
    const unicodeCandidate = unicodeLabels.find(({ index }) => index === candidate.index)?.label ?? candidate.label;
    const replacement = applyAsciiReplacements(unicodeCandidate.toLowerCase());
    const confusableKey = toConfusableKey(unicodeCandidate.toLowerCase());

    for (const reference of references) {
      const evidenceGroupId = `brand-label:${candidate.index}:${reference.domain}`;
      if (replacement?.candidate === reference.label) {
        makeFinding(findings, {
          id: `ascii-replacement:${candidate.index}:${reference.domain}`,
          evidenceGroupId,
          mechanism: 'brand-label-lookalike',
          kind: 'ascii_replacement',
          strength: 'strong',
          matchedDomain: reference.domain,
          explanation: `Доменное имя визуально заменяет часть «${reference.label}»: ${replacement.descriptions.join('; ')}. Это сходство, а не подтверждение фишинга.`,
        });
      }

      const referenceKey = toConfusableKey(reference.label);
      const unicodeMatch =
        /[^\x00-\x7f]/u.test(unicodeCandidate) &&
        confusableKey === referenceKey &&
        unicodeCandidate.toLowerCase() !== reference.label;
      if (unicodeMatch) {
        makeFinding(findings, {
          id: `unicode-confusable:${candidate.index}:${reference.domain}`,
          evidenceGroupId,
          mechanism: 'brand-label-lookalike',
          kind: 'unicode_confusable',
          strength: 'strong',
          matchedDomain: reference.domain,
          explanation: `Символы доменного имени визуально похожи на «${reference.label}» по ограниченной таблице Unicode ${UNICODE_CONFUSABLES_VERSION}.`,
        });
      }

      if (
        !replacement &&
        !unicodeMatch &&
        hasSingleEditDistance(unicodeCandidate.toLowerCase(), reference.label)
      ) {
        makeFinding(findings, {
          id: `edit-distance:${candidate.index}:${reference.domain}`,
          evidenceGroupId,
          mechanism: 'brand-label-lookalike',
          kind: 'edit_distance',
          strength: 'weak',
          matchedDomain: reference.domain,
          explanation: `Доменная метка отличается от «${reference.label}» одной опечаткой. Короткое расстояние само по себе не доказывает имитацию.`,
        });
      }
    }
  }

  if (subdomain) {
    const subdomainLabels = subdomain.split('.');
    for (const reference of references) {
      const matchingIndexes = subdomainLabels
        .map((label, index) => ({ label, index }))
        .filter(({ label }) => label === reference.label)
        .map(({ index }) => index);

      if (matchingIndexes.length > 0) {
        const evidenceGroupId = `brand-subdomain:${reference.domain}:${matchingIndexes.join(',')}`;
        makeFinding(findings, {
          id: `brand-in-subdomain:${reference.domain}:${matchingIndexes.join(',')}`,
          evidenceGroupId,
          mechanism: 'brand-in-subdomain',
          kind: 'brand_in_subdomain',
          strength: 'strong',
          matchedDomain: reference.domain,
          explanation: `«${reference.label}» находится в поддомене, а не в регистрируемом домене ${reference.domain}; это не официальный домен ${reference.label}.`,
        });
      }
    }
  }

  return [...findings.values()];
}

function invalidResult(
  input: string,
  reasonCode: 'invalid_trusted_domain',
  explanation: string,
): DomainAnalysisResult {
  return { status: 'invalid', input, reasonCode, explanation };
}

export function analyzeHostname(
  hostname: string,
  options: AnalyzeHostnameOptions = {},
): DomainAnalysisResult {
  let userTrustedDomains: readonly TrustedDomain[];
  try {
    userTrustedDomains = parseTrustedDomains(options.trustedDomains);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    return invalidResult(hostname, 'invalid_trusted_domain', error.message);
  }
  const references = [...BUILT_IN_TRUSTED_DOMAINS, ...userTrustedDomains];

  const normalized = normalizeHostname(hostname);
  if (normalized.status === 'invalid') {
    const explanations = {
      empty_input: 'Hostname не может быть пустым.',
      not_hostname: 'Ожидался только hostname, не URL, email, порт или credentials.',
      invalid_hostname: 'Строка не является допустимым hostname.',
      invalid_idna: 'Punycode не прошёл проверку декодирования и обратного преобразования.',
    } as const;
    return {
      status: 'invalid',
      input: hostname,
      reasonCode: normalized.reasonCode,
      explanation: explanations[normalized.reasonCode],
    };
  }

  if (normalized.status === 'unsupported') {
    return {
      status: 'unsupported',
      input: hostname,
      normalizedHostname: normalized.normalizedHostname,
      findings: [],
      reasonCode: normalized.reasonCode,
      explanation:
        normalized.reasonCode === 'ip_literal'
          ? 'IP-адреса не входят в область анализа доменных имён.'
          : 'Локальные hostname не анализируются как публичные домены.',
    };
  }

  const parts = parseDomain(normalized.normalizedHostname);
  const findings = collectFindings(
    normalized.normalizedHostname,
    normalized.unicodeHostname,
    parts.comparisonDomain,
    parts.subdomain,
    references,
  );

  if (parts.suffixType === 'unknown') {
    return {
      status: 'unsupported',
      input: hostname,
      normalizedHostname: normalized.normalizedHostname,
      findings,
      reasonCode: 'unknown_suffix',
      suffixType: 'unknown',
      explanation: 'Суффикс отсутствует в ICANN/PRIVATE PSL и не распознан как special-use; граница регистрации неизвестна.',
    };
  }

  if (!parts.comparisonDomain) {
    return {
      status: 'unsupported',
      input: hostname,
      normalizedHostname: normalized.normalizedHostname,
      findings,
      reasonCode: 'suffix_only',
      suffixType: parts.suffixType,
      explanation: 'Hostname содержит только public suffix и не имеет надёжно определяемого registrable domain.',
    };
  }

  if (parts.suffixType === 'special-use' && !SUPPORTED_SPECIAL_USE_SUFFIXES.has(parts.publicSuffix ?? '')) {
    return {
      status: 'unsupported',
      input: hostname,
      normalizedHostname: normalized.normalizedHostname,
      findings,
      reasonCode: 'unsupported_special_use',
      suffixType: 'special-use',
      comparisonDomain: parts.comparisonDomain,
      explanation: 'Этот special-use суффикс не входит в явно поддерживаемое тестовое пространство v0.2.',
    };
  }

  if (containsUnsupportedScript(normalized.unicodeHostname)) {
    return {
      status: 'unsupported',
      input: hostname,
      normalizedHostname: normalized.normalizedHostname,
      findings,
      reasonCode: 'unsupported_script',
      suffixType: parts.suffixType,
      comparisonDomain: parts.comparisonDomain,
      explanation: 'В hostname есть письменность вне ограниченного набора Latin/Cyrillic/Greek; анализ неполный.',
    };
  }

  return {
    status: 'success',
    input: hostname,
    normalizedHostname: normalized.normalizedHostname,
    suffixType: parts.suffixType,
    ...(parts.registrableDomain ? { registrableDomain: parts.registrableDomain } : {}),
    comparisonDomain: parts.comparisonDomain,
    findings,
    suspicion: classifySuspicion(findings),
  };
}
