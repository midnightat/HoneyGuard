import type { DomainFinding, DomainSuspicion } from './types';

export function classifySuspicion(findings: readonly DomainFinding[]): DomainSuspicion {
  const strongestByMechanism = new Map<DomainFinding['mechanism'], 'weak' | 'strong'>();

  for (const finding of findings) {
    const current = strongestByMechanism.get(finding.mechanism);
    if (current !== 'strong' && finding.strength === 'strong') {
      strongestByMechanism.set(finding.mechanism, 'strong');
    } else if (current === undefined) {
      strongestByMechanism.set(finding.mechanism, 'weak');
    }
  }

  let strongMechanisms = 0;
  let weakMechanisms = 0;
  for (const strength of strongestByMechanism.values()) {
    if (strength === 'strong') strongMechanisms += 1;
    else weakMechanisms += 1;
  }

  if (strongMechanisms >= 2) return 'high';
  if (strongMechanisms === 1) return 'medium';
  return weakMechanisms > 0 ? 'low' : 'none';
}
