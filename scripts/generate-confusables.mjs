import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sourcePath = resolve(root, 'data/unicode/18.0.0/confusables.txt');
const metadataPath = resolve(root, 'data/unicode/18.0.0/source.json');
const outputPath = resolve(root, 'src/detection/domain/confusables.generated.json');
const checkOnly = process.argv.includes('--check');
const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
const source = await readFile(sourcePath);
const actualHash = createHash('sha256').update(source).digest('hex');

if (source.byteLength !== metadata.sourceBytes || actualHash !== metadata.sha256) {
  throw new Error(`Unicode source integrity check failed: got ${source.byteLength} bytes, SHA-256 ${actualHash}`);
}

const sourceText = source.toString('utf8');
if (!sourceText.includes(`# Version: ${metadata.unicodeVersion}\n`)) {
  throw new Error(`Unicode source header does not declare version ${metadata.unicodeVersion}`);
}

const scriptMatchers = [
  /\p{Script=Latin}/u,
  /\p{Script=Cyrillic}/u,
  /\p{Script=Greek}/u,
];
const mappings = Object.create(null);
let parsedCount = 0;
let multiCodePointTargets = 0;

for (const [lineIndex, line] of sourceText.split('\n').entries()) {
  const content = line.split('#', 1)[0].trim();
  if (!content) continue;

  const match = /^([0-9A-F ]+)\s*;\s*([0-9A-F ]+)\s*;\s*([A-Z]+)\s*$/.exec(content);
  if (!match) {
    throw new Error(`Malformed Unicode mapping at line ${lineIndex + 1}`);
  }

  const [, sourceField, targetField, status] = match;
  if (status !== metadata.mappingStatus) continue;

  const sourcePoints = sourceField.trim().split(/\s+/);
  const targetPoints = targetField.trim().split(/\s+/);
  if (sourcePoints.length !== 1 || targetPoints.length === 0) {
    throw new Error(`Unexpected source or empty target sequence at line ${lineIndex + 1}`);
  }

  const sourcePoint = Number.parseInt(sourcePoints[0], 16);
  const sourceCharacter = String.fromCodePoint(sourcePoint);
  if (!scriptMatchers.some((matcher) => matcher.test(sourceCharacter))) continue;

  const key = sourcePoint.toString(16).toUpperCase();
  if (Object.hasOwn(mappings, key)) {
    throw new Error(`Duplicate Unicode source code point U+${key}`);
  }

  const target = targetPoints.map((point) => String.fromCodePoint(Number.parseInt(point, 16))).join('');
  mappings[key] = target;
  parsedCount += 1;
  if (targetPoints.length > 1) multiCodePointTargets += 1;
}

const generated = `${JSON.stringify({
  unicodeVersion: metadata.unicodeVersion,
  mappings,
}, null, 2)}\n`;

if (checkOnly) {
  const current = await readFile(outputPath, 'utf8').catch((error) => {
    if (error?.code === 'ENOENT') {
      throw new Error('Generated Unicode table is missing; run npm run generate:confusables.');
    }
    throw error;
  });
  if (current !== generated) {
    throw new Error('Generated Unicode table is stale; run npm run generate:confusables.');
  }
} else {
  await writeFile(outputPath, generated, 'utf8');
}

console.log(`Unicode ${metadata.unicodeVersion}: ${parsedCount} mappings, ${multiCodePointTargets} multi-code-point targets${checkOnly ? ' verified' : ' generated'}.`);
