import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const css = readFileSync(new URL('../src/popup/popup.css', import.meta.url), 'utf8');
const popupRule = css.match(/\.popup\s*\{([^}]*)\}/su)?.[1];
const findingsRule = css.match(/\.popup__finding-list\s*\{([^}]*)\}/su)?.[1];

assert.ok(popupRule, 'Popup root CSS rule is missing.');
assert.ok(findingsRule, 'Findings list CSS rule is missing.');
assert.match(popupRule, /width:\s*380px\b/u);
assert.doesNotMatch(
  popupRule,
  /\b(?:min-|max-)?height\s*:|\boverflow(?:-[a-z]+)?\s*:/u,
  'The popup root must grow with its content instead of clipping or scrolling it.',
);
assert.match(findingsRule, /max-height:\s*120px\b/u);
assert.match(findingsRule, /overflow-y:\s*auto\b/u);

console.log('Popup layout rules verified.');
