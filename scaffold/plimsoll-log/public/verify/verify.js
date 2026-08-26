// PLIMSOLL browser verifier — same-origin only, no third-party requests.
(function () {
  const attEl = document.getElementById('att');
  const bundleEl = document.getElementById('bundle');
  const logEl = document.getElementById('log');
  const runBtn = document.getElementById('run');
  const statusEl = document.getElementById('status');
  const verdictEl = document.getElementById('verdict');
  const discEl = document.getElementById('disclosure');
  const checksBody = document.querySelector('#checks tbody');

  const params = new URLSearchParams(location.search);
  if (params.get('log')) logEl.value = decodeURIComponent(params.get('log'));

  function ready() { runBtn.disabled = !attEl.value.trim(); }
  attEl.addEventListener('input', ready);
  bundleEl.addEventListener('input', ready);

  function loadFile(input, target) {
    input.addEventListener('change', () => {
      const f = input.files && input.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => { target.value = r.result; ready(); };
      r.readAsText(f);
    });
  }
  loadFile(document.getElementById('att-file'), attEl);
  loadFile(document.getElementById('bundle-file'), bundleEl);

  attEl.addEventListener('dragover', e => e.preventDefault());
  attEl.addEventListener('drop', e => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => { attEl.value = r.result; ready(); };
    r.readAsText(f);
  });

  let goReady = null;
  async function initGo() {
    if (goReady) return goReady;
    goReady = (async () => {
      const go = new Go();
      const res = await fetch('plimsoll_verify.wasm');
      const buf = await res.arrayBuffer();
      const { instance } = await WebAssembly.instantiate(buf, go.importObject);
      go.run(instance);
    })();
    return goReady;
  }

  async function fetchCheckpoint(base) {
    const url = base.replace(/\/+$/, '') + '/checkpoint';
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error('checkpoint fetch failed: ' + res.status);
    return res.text();
  }

  function renderReport(report) {
    verdictEl.textContent = report.verdict;
    verdictEl.className = report.verdict === 'VERIFIED' ? 'pass'
      : report.verdict === 'VERIFIED WITH DISCLOSURES' ? 'disc' : 'fail';
    discEl.textContent = '';
    if (report.disclosure) {
      const d = report.disclosure;
      const parts = (d.attempts || []).map(a => '#' + a.attempt_no + '=' + a.verdict);
      discEl.textContent = 'Attempt ' + d.attempt_no + ' of ' + d.total_attempts
        + (parts.length ? ' [' + parts.join(', ') + ']' : '')
        + (d.supersedes ? '; supersedes ' + d.supersedes : '');
    }
    checksBody.innerHTML = '';
    (report.checks || []).forEach(c => {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + esc(c.id) + '</td><td>' + (c.pass ? 'PASS' : 'FAIL') + '</td><td>' + esc(c.reason) + '</td>';
      checksBody.appendChild(tr);
    });
  }

  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  runBtn.addEventListener('click', async () => {
    statusEl.textContent = 'Loading verifier…';
    verdictEl.textContent = '';
    discEl.textContent = '';
    checksBody.innerHTML = '';
    try {
      await initGo();
      const attJSON = attEl.value.trim();
      const bundleJSON = bundleEl.value.trim();
      let latestCP = '';
      const offline = bundleJSON.length > 0;
      if (!offline) {
        const logURL = logEl.value.trim();
        if (!logURL) throw new Error('Enter a log URL or provide an offline bundle');
        statusEl.textContent = 'Fetching signed checkpoint (only network request)…';
        latestCP = await fetchCheckpoint(logURL);
      } else {
        statusEl.textContent = 'Verifying offline (no network)…';
      }
      const out = plimsollVerify(attJSON, bundleJSON, latestCP, offline);
      if (!out.ok) throw new Error(out.error);
      const report = JSON.parse(out.report);
      renderReport(report);
      statusEl.textContent = offline ? 'Done — zero network requests.' : 'Done — one checkpoint request.';
    } catch (e) {
      statusEl.innerHTML = '<span class="err">' + esc(e.message) + '</span>';
    }
  });

  ready();
})();
