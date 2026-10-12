export type DetectionSeverity = 'info' | 'warning' | 'danger';

export interface DetectionContext {
  readonly senderAddress: string;
  readonly senderDomain: string;
  readonly urls: readonly string[];
}

export interface DetectionFinding {
  readonly ruleId: string;
  readonly severity: DetectionSeverity;
  readonly title: string;
  readonly explanation: string;
}

export interface Detector {
  readonly id: string;
  analyze(context: DetectionContext): readonly DetectionFinding[];
}
