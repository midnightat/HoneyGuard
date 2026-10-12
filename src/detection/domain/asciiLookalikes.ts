export interface AsciiReplacement {
  readonly pattern: RegExp;
  readonly replacement: string;
  readonly description: string;
}

const ASCII_REPLACEMENTS: readonly AsciiReplacement[] = [
  { pattern: /rn/gu, replacement: 'm', description: 'rn выглядит как m' },
  { pattern: /1/gu, replacement: 'l', description: 'цифра 1 заменяет букву l' },
  { pattern: /0/gu, replacement: 'o', description: 'цифра 0 заменяет букву o' },
];

export interface ReplacementMatch {
  readonly candidate: string;
  readonly descriptions: readonly string[];
}

export function applyAsciiReplacements(label: string): ReplacementMatch | null {
  let candidate = label;
  const descriptions: string[] = [];

  for (const replacement of ASCII_REPLACEMENTS) {
    const nextCandidate = candidate.replace(replacement.pattern, replacement.replacement);
    if (nextCandidate !== candidate) {
      candidate = nextCandidate;
      descriptions.push(replacement.description);
    }
  }

  return descriptions.length > 0 ? { candidate, descriptions } : null;
}

export function hasSingleEditDistance(left: string, right: string): boolean {
  if (left === right || Math.abs(left.length - right.length) > 1) return false;

  let leftIndex = 0;
  let rightIndex = 0;
  let edits = 0;

  while (leftIndex < left.length && rightIndex < right.length) {
    if (left[leftIndex] === right[rightIndex]) {
      leftIndex += 1;
      rightIndex += 1;
      continue;
    }

    edits += 1;
    if (edits > 1) return false;

    if (left.length === right.length) {
      if (
        leftIndex + 1 < left.length &&
        rightIndex + 1 < right.length &&
        left[leftIndex] === right[rightIndex + 1] &&
        left[leftIndex + 1] === right[rightIndex]
      ) {
        leftIndex += 2;
        rightIndex += 2;
      } else {
        leftIndex += 1;
        rightIndex += 1;
      }
    } else if (left.length > right.length) {
      leftIndex += 1;
    } else {
      rightIndex += 1;
    }
  }

  if (leftIndex < left.length || rightIndex < right.length) edits += 1;
  return edits === 1;
}
