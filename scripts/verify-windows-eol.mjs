import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, rm, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporaryRoot = await mkdtemp(resolve(tmpdir(), 'honeyguard-windows-eol-'));
const files = [
  '.gitattributes',
  'data/unicode/18.0.0/confusables.txt',
  'data/unicode/18.0.0/source.json',
  'scripts/generate-confusables.mjs',
  'src/detection/domain/confusables.generated.json',
];

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed:\n${result.stderr || result.stdout}`);
  }
}

try {
  for (const file of files) {
    const destination = resolve(temporaryRoot, file);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(resolve(projectRoot, file), destination);
  }

  run('git', ['init', '--quiet'], temporaryRoot);
  run('git', ['-c', 'core.autocrlf=true', 'add', '--', ...files], temporaryRoot);

  await unlink(resolve(temporaryRoot, 'data/unicode/18.0.0/confusables.txt'));
  await unlink(resolve(temporaryRoot, 'src/detection/domain/confusables.generated.json'));
  run('git', ['-c', 'core.autocrlf=true', 'checkout-index', '--all', '--force'], temporaryRoot);
  run(
    process.execPath,
    ['scripts/generate-confusables.mjs', '--check'],
    temporaryRoot,
  );

  console.log('Unicode generator passes after a simulated Windows CRLF checkout.');
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
