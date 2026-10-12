function readWhatwgHostname(input) {
  try {
    return new URL(`http://${input}/`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function appendCell(row, value) {
  const cell = document.createElement('td');
  cell.textContent = value;
  row.append(cell);
}

async function run() {
  const status = document.getElementById('status');
  const results = document.getElementById('results');
  if (!(status instanceof HTMLElement) || !(results instanceof HTMLElement)) {
    throw new Error('Harness result elements are missing.');
  }

  const response = await fetch('./cases.json');
  if (!response.ok) throw new Error(`Could not load shared test cases (${response.status}).`);

  const fixture = await response.json();
  let failed = 0;

  for (const testCase of fixture.cases) {
    const actual = readWhatwgHostname(testCase.input);
    const passed = actual === testCase.expectedWhatwgHostname;
    if (!passed) failed += 1;

    const row = document.createElement('tr');
    appendCell(row, testCase.id);
    appendCell(row, testCase.input || '(empty)');
    appendCell(row, testCase.expectedWhatwgHostname ?? '(URL parser rejects)');
    appendCell(row, actual ?? '(URL parser rejects)');
    const result = document.createElement('td');
    result.textContent = passed ? 'PASS' : 'FAIL';
    result.className = passed ? 'pass' : 'fail';
    row.append(result);
    results.append(row);
  }

  status.textContent = `${fixture.cases.length - failed}/${fixture.cases.length} URL fixtures passed in Chrome.`;
  status.setAttribute('role', failed === 0 ? 'status' : 'alert');
  if (failed > 0) status.classList.add('fail');
}

run().catch((error) => {
  const status = document.getElementById('status');
  if (status instanceof HTMLElement) {
    status.textContent = `Harness failed: ${error instanceof Error ? error.message : String(error)}`;
    status.setAttribute('role', 'alert');
  }
});
