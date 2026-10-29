/* PrivacyLens – content.js: runs in the page, talks only to the extension background. */
(function () {
  'use strict';
  if (window.__plLoaded) return;
  window.__plLoaded = true;
  const PL = globalThis.PL;
  let registry = new Map();
  let lastOpts = {};

  function confirmUI(text) {
    return new Promise((resolve) => {
      const host = document.createElement('div');
      host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;display:flex;align-items:flex-end;justify-content:center;pointer-events:none';
      const sh = host.attachShadow({ mode: 'closed' }); // page scripts cannot reach into a closed root
      sh.innerHTML = `<style>
        .box{pointer-events:auto;margin:24px;max-width:460px;background:#14181f;color:#e8ecf1;font:14px/1.45 system-ui,sans-serif;border:1px solid #3a4658;border-left:4px solid #e0b341;border-radius:6px;padding:14px 16px;box-shadow:0 8px 30px #0008}
        b{display:block;margin-bottom:6px}p{margin:0 0 12px;word-break:break-word}
        button{font:inherit;padding:6px 14px;margin-right:8px;border-radius:4px;border:1px solid #556;background:#222b38;color:#fff;cursor:pointer}
        #y{background:#e0b341;color:#14181f;border-color:#e0b341;font-weight:600}</style>
        <div class="box" role="alertdialog"><b>PrivacyLens needs your approval</b><p></p><button id="y">Allow</button><button id="n">Deny</button></div>`;
      sh.querySelector('p').textContent = text;
      let done = false;
      const finish = (v) => (e) => { if (!e.isTrusted || done) return; done = true; host.remove(); resolve(v); }; // ignore synthetic clicks from page scripts
      sh.getElementById('y').addEventListener('click', finish(true));
      sh.getElementById('n').addEventListener('click', finish(false));
      setTimeout(() => { if (!done) { done = true; host.remove(); resolve(false); } }, 90000); // fail closed
      document.documentElement.appendChild(host);
    });
  }

  chrome.runtime.onMessage.addListener((msg, _sender, send) => {
    (async () => {
      try {
        if (msg.type === 'PL_SNAPSHOT') {
          lastOpts = { rules: msg.rules, strictMessages: msg.strict };
          const snap = PL.snapshot(document, lastOpts);
          registry = snap.registry;
          const out = { url: snap.url, title: snap.title, text: snap.text, meta: snap.meta, stats: snap.stats, known: snap.known };
          if (msg.preview) out.lines = snap.lines; // raw lines only ever go to the extension popup, never to a model
          send(out);
        } else if (msg.type === 'PL_REGIONS') {
          send(PL.collectRegions(document, { rules: msg.rules, strictMessages: msg.strict }));
        } else if (msg.type === 'PL_EXEC') {
          const res = await PL.execute(document, registry, msg.action, (key) =>
            chrome.runtime.sendMessage({ type: 'PL_VAULT_GET', key }).then((r) => (r && r.ok ? r.value : null)), lastOpts);
          send(res);
        } else if (msg.type === 'PL_CONFIRM') {
          send(await confirmUI(msg.text));
        }
      } catch (e) { send({ ok: false, error: String(e && e.message || e) }); }
    })();
    return true;
  });
})();
