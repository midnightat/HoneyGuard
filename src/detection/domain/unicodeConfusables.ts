import generated from './confusables.generated.json';

const CONFUSABLES = new Map(
  Object.entries(generated.mappings).map(([codePoint, target]) => [
    Number.parseInt(codePoint, 16),
    target,
  ]),
);

export function toConfusableKey(label: string): string {
  let result = '';
  for (const character of label) {
    const codePoint = character.codePointAt(0);
    result += codePoint === undefined ? character : CONFUSABLES.get(codePoint) ?? character;
  }
  return result;
}

export function containsUnsupportedScript(hostname: string): boolean {
  const supportedScripts = [
    /\p{Script=Latin}/u,
    /\p{Script=Cyrillic}/u,
    /\p{Script=Greek}/u,
    /\p{Script=Common}/u,
    /\p{Script=Inherited}/u,
  ];

  for (const character of hostname) {
    if (!/[\p{L}\p{M}]/u.test(character)) continue;
    if (!supportedScripts.some((matcher) => matcher.test(character))) return true;
  }
  return false;
}

export const UNICODE_CONFUSABLES_VERSION = generated.unicodeVersion;
