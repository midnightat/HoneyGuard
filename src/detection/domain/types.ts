export type DomainSuspicion = 'none' | 'low' | 'medium' | 'high';

export type SuffixType = 'icann' | 'private' | 'special-use' | 'unknown';

export type DomainReasonCode =
  | 'empty_input'
  | 'not_hostname'
  | 'invalid_hostname'
  | 'invalid_idna'
  | 'ip_literal'
  | 'local_hostname'
  | 'suffix_only'
  | 'unknown_suffix'
  | 'unsupported_special_use'
  | 'unsupported_script'
  | 'invalid_trusted_domain';

export type DomainFindingKind =
  | 'ascii_replacement'
  | 'edit_distance'
  | 'unicode_confusable'
  | 'brand_in_subdomain'
  | 'mixed_script';

export type DomainEvidenceMechanism =
  | 'brand-label-lookalike'
  | 'brand-in-subdomain'
  | 'mixed-script';

export interface DomainFinding {
  readonly id: string;
  readonly evidenceGroupId: string;
  readonly mechanism: DomainEvidenceMechanism;
  readonly kind: DomainFindingKind;
  readonly strength: 'weak' | 'strong';
  readonly explanation: string;
  readonly matchedDomain?: string;
}

interface DomainResultBase {
  readonly input: string;
  readonly normalizedHostname?: string;
  readonly findings: readonly DomainFinding[];
}

export interface SuccessfulDomainAnalysis extends DomainResultBase {
  readonly status: 'success';
  readonly suspicion: DomainSuspicion;
  readonly normalizedHostname: string;
  readonly suffixType: Exclude<SuffixType, 'unknown'>;
  readonly registrableDomain?: string;
  readonly comparisonDomain?: string;
}

export interface InvalidDomainAnalysis {
  readonly status: 'invalid';
  readonly input: string;
  readonly reasonCode: Extract<
    DomainReasonCode,
    'empty_input' | 'not_hostname' | 'invalid_hostname' | 'invalid_idna' | 'invalid_trusted_domain'
  >;
  readonly explanation: string;
}

export interface UnsupportedDomainAnalysis extends DomainResultBase {
  readonly status: 'unsupported';
  readonly reasonCode: Extract<
    DomainReasonCode,
    | 'ip_literal'
    | 'local_hostname'
    | 'suffix_only'
    | 'unknown_suffix'
    | 'unsupported_special_use'
    | 'unsupported_script'
  >;
  readonly explanation: string;
  readonly suffixType?: SuffixType;
  readonly comparisonDomain?: string;
}

export type DomainAnalysisResult =
  | SuccessfulDomainAnalysis
  | InvalidDomainAnalysis
  | UnsupportedDomainAnalysis;

export interface AnalyzeHostnameOptions {
  readonly trustedDomains?: readonly string[];
}
