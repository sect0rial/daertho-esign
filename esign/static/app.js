/*! Daertho E-Sign — owner app shell (vanilla JS, no dependencies).
 *
 *  Boot: GET /v1/brand (name, logo) and GET /v1/auth/me → {user:{id,email,name,role}|null, setup_needed:bool}.
 *    - setup_needed  → first-run form (POST /v1/auth/setup) creates the first admin
 *    - no user       → sign-in form (POST /v1/auth/login)
 *    - signed in     → top bar + the envelope app (window.ESign, esign.js) mounted full-page
 *  Routes (hash): #envelopes (default) · #envelope/<id> · #verify · #settings
 *  Auth is the same-origin session cookie only; API keys are created here for scripts, never used by the browser.
 */
(function () {
  'use strict';

  var root = document.getElementById('app');
  var BRAND = { name: 'E-Sign', logo_url: '', powered_by: true, support_email: '' };
  var ME = null;                 // {id, email, name, role}
  var view = '';                 // 'envelopes' | 'settings'
  var mountedEsign = false;
  var stage = null;              // element the current view renders into
  var routing = false;           // true while we write the hash ourselves

  /* ---------------------------------------------------------------- tiny DOM helpers */
  function str(v) { return v == null ? '' : String(v); }
  function h(tag, attrs) {
    var n = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === 'class') n.className = v;
        else if (k === 'text') n.textContent = String(v);
        else if (k === 'on') Object.keys(v).forEach(function (ev) { n.addEventListener(ev, v[ev]); });
        else if (k === 'value') n.value = v;
        else n.setAttribute(k, v === true ? '' : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) add(n, arguments[i]);
    return n;
  }
  function add(n, c) {
    if (c == null || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(n, x); }); return; }
    n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function brandName() { return str(BRAND.name).trim() || 'E-Sign'; }
  function fmt(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return str(iso);
    try { return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
    catch (e) { return d.toISOString(); }
  }

  /* ---------------------------------------------------------------- HTTP (cookie session) */
  function api(method, path, body) {
    var opts = { method: method, credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' } };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    return fetch(path, opts).then(null, function () {
      var e = new Error('Can’t reach the server. Check your connection and try again.'); e.status = 0; throw e;
    }).then(function (r) {
      return r.text().then(function (t) {
        var data = null;
        try { data = t ? JSON.parse(t) : null; } catch (e) { data = t; }
        if (!r.ok) {
          var d = data && typeof data === 'object' ? data.detail : data;
          if (Array.isArray(d)) d = d.map(function (x) { return x && x.msg ? x.msg : str(x); }).join(' ');
          var err = new Error(str(d) || ('Request failed (' + r.status + ').'));
          err.status = r.status; throw err;
        }
        return data;
      });
    });
  }
  function listOf(data, key) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data[key])) return data[key];
    return [];
  }

  /* ---------------------------------------------------------------- boot */
  function boot() {
    var brand = api('GET', '/v1/brand').then(function (b) {
      if (b && typeof b === 'object') {
        BRAND = { name: str(b.name).trim() || 'E-Sign', logo_url: str(b.logo_url), powered_by: b.powered_by !== false,
          support_email: str(b.support_email) };
      }
    }, function () { /* defaults */ });
    var me = api('GET', '/v1/auth/me').then(function (m) { return m || {}; }, function (err) {
      if (err.status === 401) return { user: null, setup_needed: false };
      throw err;
    });
    Promise.all([brand, me]).then(function (r) {
      var m = r[1];
      document.title = brandName();
      if (m.user) { ME = m.user; startApp(); }
      else if (m.setup_needed) renderSetup();
      else renderLogin();
    }, function (err) { renderFatal(err); });
  }

  function renderFatal(err) {
    clear(root);
    root.appendChild(authShell('Something went wrong', [
      h('p', { class: 'app-p', text: (err && err.message) || 'The app couldn’t start.' }),
      h('button', { type: 'button', class: 'app-btn app-btn-p', text: 'Try again', on: { click: function () { location.reload(); } } })
    ]));
  }

  /* ---------------------------------------------------------------- sign-in / first-run */
  function logoEl(cls) {
    var logo = str(BRAND.logo_url).trim();
    if (logo && /^(https:\/\/|\/)/i.test(logo)) return h('img', { class: cls + '-logo', src: logo, alt: brandName() });
    return h('span', { class: cls + '-word' }, h('span', { class: 'app-mark', 'aria-hidden': 'true' }), h('span', { text: brandName() }));
  }
  function authShell(title, body) {
    return h('main', { class: 'app-auth' },
      h('div', { class: 'app-auth-card' },
        h('div', { class: 'app-auth-brand' }, logoEl('app-auth')),
        h('h1', { class: 'app-h1', tabindex: '-1', text: title }),
        body),
      BRAND.powered_by ? h('p', { class: 'app-powered', text: 'Powered by Daertho E-Sign' }) : null);
  }
  function inputField(label, attrs) {
    var id = 'f' + Math.random().toString(36).slice(2, 8);
    attrs.id = id; attrs.class = 'app-in';
    var input = h('input', attrs);
    return { wrap: h('div', { class: 'app-field' }, h('label', { class: 'app-lbl', for: id, text: label }), input), input: input };
  }
  function renderLogin() {
    clear(root);
    document.title = 'Sign in — ' + brandName();
    var em = inputField('Email', { type: 'email', autocomplete: 'username', required: true, maxlength: '254' });
    var pw = inputField('Password', { type: 'password', autocomplete: 'current-password', required: true, maxlength: '200' });
    var err = h('p', { class: 'app-err', role: 'alert' });
    var btn = h('button', { type: 'submit', class: 'app-btn app-btn-p app-btn-block', text: 'Sign in' });
    var form = h('form', { class: 'app-form', novalidate: true }, em.wrap, pw.wrap, err, btn);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      err.textContent = '';
      if (!em.input.value.trim() || !pw.input.value) { err.textContent = 'Enter your email and password.'; return; }
      btn.disabled = true; btn.textContent = 'Signing in…';
      api('POST', '/v1/auth/login', { email: em.input.value.trim(), password: pw.input.value }).then(function (r) {
        ME = (r && r.user) || r;
        if (!ME || !ME.id) return api('GET', '/v1/auth/me').then(function (m) { ME = m && m.user; if (!ME) throw new Error('Sign-in didn’t stick. Are cookies blocked?'); });
      }).then(function () { pw.input.value = ''; startApp(); }, function (e2) {
        btn.disabled = false; btn.textContent = 'Sign in';
        err.textContent = e2.status === 401 ? 'That email and password don’t match an account.' : e2.message;
        pw.input.focus(); pw.input.select();
      });
    });
    root.appendChild(authShell('Sign in', [form,
      BRAND.support_email ? h('p', { class: 'app-hint' }, 'Need an account? Ask your administrator' + (BRAND.support_email ? ' (' + BRAND.support_email + ')' : '') + '.') : null]));
    em.input.focus();
  }
  function renderSetup() {
    clear(root);
    document.title = 'Set up — ' + brandName();
    var nm = inputField('Your name', { type: 'text', autocomplete: 'name', maxlength: '120' });
    var em = inputField('Email', { type: 'email', autocomplete: 'username', required: true, maxlength: '254' });
    var pw = inputField('Password (10 characters or more)', { type: 'password', autocomplete: 'new-password', required: true, minlength: '10', maxlength: '200' });
    var pw2 = inputField('Repeat the password', { type: 'password', autocomplete: 'new-password', required: true, maxlength: '200' });
    var err = h('p', { class: 'app-err', role: 'alert' });
    var btn = h('button', { type: 'submit', class: 'app-btn app-btn-p app-btn-block', text: 'Create admin account' });
    var form = h('form', { class: 'app-form', novalidate: true }, nm.wrap, em.wrap, pw.wrap, pw2.wrap, err, btn);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      err.textContent = '';
      var email = em.input.value.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) { err.textContent = 'Enter a valid email address.'; em.input.focus(); return; }
      if (pw.input.value.length < 10) { err.textContent = 'Use a password of at least 10 characters.'; pw.input.focus(); return; }
      if (pw.input.value !== pw2.input.value) { err.textContent = 'The passwords don’t match.'; pw2.input.focus(); return; }
      btn.disabled = true; btn.textContent = 'Creating…';
      api('POST', '/v1/auth/setup', { email: email, password: pw.input.value, name: nm.input.value.trim() }).then(function () {
        return api('GET', '/v1/auth/me');
      }).then(function (m) {
        if (m && m.user) { ME = m.user; startApp(); }
        else renderLogin();
      }, function (e2) {
        btn.disabled = false; btn.textContent = 'Create admin account';
        err.textContent = e2.status === 409 ? 'This server is already set up. Sign in instead.' : e2.message;
        if (e2.status === 409) setTimeout(renderLogin, 1500);
      });
    });
    root.appendChild(authShell('Set up ' + brandName(), [
      h('p', { class: 'app-p', text: 'Create the first administrator account. You can add more people afterwards in Settings.' }), form]));
    (nm.input).focus();
  }

  /* ---------------------------------------------------------------- signed-in app */
  var bar = null, navBtns = {};
  function startApp() {
    clear(root);
    document.title = brandName();
    navBtns = {};
    function nav(key, label, onClick) {
      var b = h('button', { type: 'button', class: 'app-nav-b', text: label, on: { click: onClick } });
      navBtns[key] = b;
      return b;
    }
    var userMenu = h('details', { class: 'app-user' },
      h('summary', { class: 'app-user-s', 'aria-label': 'Account' }, h('span', { class: 'app-avatar', 'aria-hidden': 'true', text: initials(ME) }),
        h('span', { class: 'app-user-n', text: str(ME.name).trim() || str(ME.email) })),
      h('div', { class: 'app-user-m' },
        h('div', { class: 'app-user-e', text: str(ME.email) }),
        h('div', { class: 'app-user-r', text: ME.role === 'admin' ? 'Administrator' : 'Member' }),
        h('button', { type: 'button', class: 'app-btn app-btn-block', text: 'Sign out', on: { click: signOut } })));
    bar = h('header', { class: 'app-bar' },
      h('a', { class: 'app-bar-brand', href: '#envelopes', 'aria-label': brandName() + ' — envelopes' }, logoEl('app-bar')),
      h('nav', { class: 'app-nav', 'aria-label': 'Main' },
        nav('envelopes', 'Envelopes', function () { go('#envelopes'); }),
        nav('verify', 'Verify a PDF', function () { go('#verify'); }),
        nav('settings', 'Settings', function () { go('#settings'); })),
      userMenu);
    document.addEventListener('click', function (e) { if (userMenu.open && !userMenu.contains(e.target)) userMenu.open = false; });
    stage = h('div', { class: 'app-stage' });
    root.appendChild(bar);
    root.appendChild(stage);
    window.addEventListener('hashchange', onHash);
    window.addEventListener('beforeunload', function (e) {
      if (mountedEsign && window.ESign && window.ESign.isDirty()) { e.preventDefault(); e.returnValue = ''; }
    });
    onHash();
  }
  function initials(u) {
    var n = str(u && (u.name || u.email)).trim().split(/[\s@.]+/).filter(Boolean);
    return ((n[0] || '?').charAt(0) + (n.length > 1 ? n[1].charAt(0) : '')).toUpperCase();
  }
  function signOut() {
    leaveEsign().then(function (ok) {
      if (!ok) return;
      api('POST', '/v1/auth/logout', {}).then(null, function () { /* the cookie is cleared server-side anyway */ }).then(function () {
        ME = null;
        unmountEsign();
        window.removeEventListener('hashchange', onHash);
        history.replaceState(null, '', location.pathname);
        renderLogin();
      });
    });
  }
  function setActive(key) {
    Object.keys(navBtns).forEach(function (k) {
      if (k === key) navBtns[k].setAttribute('aria-current', 'page'); else navBtns[k].removeAttribute('aria-current');
    });
  }
  /* navigate: let the envelope app save first (it asks if something couldn't be saved) */
  function go(hash) {
    if (location.hash === hash) { onHash(); return; }
    location.hash = hash;
  }
  function leaveEsign() {
    if (mountedEsign && window.ESign && typeof window.ESign.leave === 'function') return window.ESign.leave();
    return Promise.resolve(true);
  }
  function parseHash() {
    var hsh = (location.hash || '').replace(/^#\/?/, '');
    var m = /^envelope\/([A-Za-z0-9_-]{1,64})$/.exec(hsh);
    if (m) return { view: 'envelopes', id: m[1] };
    if (hsh === 'verify') return { view: 'envelopes', id: 'verify' };
    if (hsh === 'settings') return { view: 'settings' };
    return { view: 'envelopes', id: null };
  }
  var lastHash = null;
  function onHash() {
    if (routing) { routing = false; lastHash = location.hash; return; }
    var r = parseHash();
    var prev = lastHash;
    leaveEsign().then(function (ok) {
      if (!ok) {            // stay where we are: put the old hash back without re-routing
        if (prev != null && prev !== location.hash) { routing = true; location.hash = prev; }
        return;
      }
      lastHash = location.hash;
      if (r.view === 'settings') { showSettings(); return; }
      showEnvelopes(r.id);
    });
  }
  /* the envelope app reports which envelope is open; mirror it in the hash without re-routing */
  function onRoute(id) {
    var want = id === 'verify' ? '#verify' : id ? '#envelope/' + id : '#envelopes';
    setActive(id === 'verify' ? 'verify' : 'envelopes');
    var cur = location.hash || '#envelopes';
    if (cur === want || (!location.hash && want === '#envelopes')) { lastHash = location.hash; return; }
    routing = true;
    history.replaceState(null, '', want);
    routing = false;
    lastHash = want;
  }
  function unmountEsign() {
    if (mountedEsign && window.ESign) { try { window.ESign.unmount(); } catch (e) { /* ignore */ } }
    mountedEsign = false;
  }
  function showEnvelopes(id) {
    view = 'envelopes';
    setActive(id === 'verify' ? 'verify' : 'envelopes');
    if (!window.ESign) { renderStageError('The envelope app failed to load. Reload the page.'); return; }
    unmountEsign();
    clear(stage);
    var host = h('div', { class: 'app-esign' });
    stage.appendChild(host);
    window.ESign.mount(host, {
      brandName: brandName(),
      envelopeId: id || null,
      onRoute: onRoute,
      setTitle: function (t) {
        t = str(t).replace(/^E-Sign( · )?/, '');
        document.title = t ? t + ' — ' + brandName() : brandName();
      }
    });
    mountedEsign = true;
  }
  function renderStageError(msg) {
    unmountEsign();
    clear(stage);
    stage.appendChild(h('div', { class: 'app-page' }, h('p', { class: 'app-err', text: msg })));
  }

  /* ---------------------------------------------------------------- settings */
  function showSettings() {
    view = 'settings';
    setActive('settings');
    unmountEsign();
    clear(stage);
    document.title = 'Settings — ' + brandName();
    var page = h('div', { class: 'app-page' },
      h('div', { class: 'app-kicker', text: brandName() }),
      h('h1', { class: 'app-h1', tabindex: '-1', text: 'Settings' }));
    page.appendChild(keysSection());
    if (ME && ME.role === 'admin') page.appendChild(usersSection());
    page.appendChild(h('section', { class: 'app-sec' },
      h('h2', { class: 'app-h2', text: 'Your account' }),
      h('dl', { class: 'app-dl' },
        h('dt', { text: 'Name' }), h('dd', { text: str(ME.name).trim() || '—' }),
        h('dt', { text: 'Email' }), h('dd', { text: str(ME.email) }),
        h('dt', { text: 'Role' }), h('dd', { text: ME.role === 'admin' ? 'Administrator' : 'Member' })),
      passwordForm(),
      h('div', { class: 'app-inline' },
        h('button', { type: 'button', class: 'app-btn', text: 'Sign out', on: { click: signOut } }),
        h('button', { type: 'button', class: 'app-btn', text: 'Sign out on every device', on: { click: signOutEverywhere } }))));
    stage.appendChild(page);
    var h1 = page.querySelector('h1');
    if (h1) h1.focus();
  }

  function passwordForm() {
    var cur = inputField('Current password', { type: 'password', autocomplete: 'current-password', maxlength: '200' });
    var nw = inputField('New password (10+ characters)', { type: 'password', autocomplete: 'new-password', minlength: '10', maxlength: '200' });
    var err = h('p', { class: 'app-err', role: 'alert' });
    var ok = h('p', { class: 'app-ok', role: 'status' });
    var b = h('button', { type: 'submit', class: 'app-btn', text: 'Change password' });
    var f = h('form', { class: 'app-pwform', novalidate: true }, h('h3', { class: 'app-h3', text: 'Change your password' }),
      h('div', { class: 'app-grid-form' }, cur.wrap, nw.wrap), err, ok, b);
    f.addEventListener('submit', function (e) {
      e.preventDefault();
      err.textContent = ''; ok.textContent = '';
      if (!cur.input.value) { err.textContent = 'Enter your current password.'; cur.input.focus(); return; }
      if (nw.input.value.length < 10) { err.textContent = 'Use a new password of at least 10 characters.'; nw.input.focus(); return; }
      b.disabled = true;
      api('POST', '/v1/auth/password', { current: cur.input.value, new: nw.input.value }).then(function () {
        b.disabled = false; cur.input.value = ''; nw.input.value = '';
        ok.textContent = 'Password changed. Other devices are signed out.';
      }, function (e2) { b.disabled = false; err.textContent = e2.message; });
    });
    return f;
  }
  function signOutEverywhere() {
    if (!window.confirm('Sign out on every device, including this one?')) return;
    leaveEsign().then(function (ok) {
      if (!ok) return;
      api('POST', '/v1/auth/logout-everywhere', {}).then(null, function () { /* fall through to the sign-in page */ }).then(function () {
        ME = null; unmountEsign(); window.removeEventListener('hashchange', onHash);
        history.replaceState(null, '', location.pathname); renderLogin();
      });
    });
  }

  function table(head, rows) {
    return h('div', { class: 'app-tbl-wrap', role: 'region', tabindex: '0', 'aria-label': head.join(', ') },
      h('table', { class: 'app-tbl' },
        h('thead', null, h('tr', null, head.map(function (x) { return h('th', { scope: 'col', text: x }); }))),
        h('tbody', null, rows)));
  }

  function keysSection() {
    var sec = h('section', { class: 'app-sec' },
      h('h2', { class: 'app-h2', text: 'API keys' }),
      h('p', { class: 'app-p', text: 'Use an API key to create and send envelopes from your own systems: send it in the X-API-Key header to the /v1/esign endpoints. A key acts as you and sees your envelopes. It’s shown once, when you create it.' }));
    var list = h('div', { class: 'app-list' }, h('p', { class: 'app-hint', text: 'Loading…' }));
    var reveal = h('div', { class: 'app-reveal', hidden: true });
    var nameIn = inputField('Key name', { type: 'text', maxlength: '80', placeholder: 'e.g. CRM integration' });
    var err = h('p', { class: 'app-err', role: 'alert' });
    var create = h('button', { type: 'submit', class: 'app-btn app-btn-p', text: 'Create key' });
    var form = h('form', { class: 'app-inline' }, nameIn.wrap, create);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      err.textContent = '';
      var name = nameIn.input.value.trim();
      if (!name) { err.textContent = 'Give the key a name so you can recognise it later.'; nameIn.input.focus(); return; }
      create.disabled = true;
      api('POST', '/v1/auth/keys', { label: name }).then(function (k) {
        create.disabled = false;
        nameIn.input.value = '';
        showKey(k && (k.key || k.api_key || k.token), name);
        load();
      }, function (e2) { create.disabled = false; err.textContent = e2.message; });
    });
    function showKey(key, name) {
      clear(reveal);
      if (!key) { reveal.hidden = true; return; }
      var inp = h('input', { class: 'app-in app-mono', readonly: true, value: key, 'aria-label': 'New API key' });
      var copy = h('button', { type: 'button', class: 'app-btn', text: 'Copy', on: { click: function () {
        var done = function () { copy.textContent = 'Copied'; setTimeout(function () { copy.textContent = 'Copy'; }, 1600); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(key).then(done, function () { inp.select(); });
        else { inp.select(); try { document.execCommand('copy'); done(); } catch (e) { /* the user can copy by hand */ } }
      } } });
      add(reveal, [h('p', { class: 'app-strong', text: 'Your new key “' + name + '”' }),
        h('p', { class: 'app-hint', text: 'Copy it now and store it somewhere safe. You won’t be able to see it again.' }),
        h('div', { class: 'app-inline' }, inp, copy),
        h('button', { type: 'button', class: 'app-linkbtn', text: 'I’ve saved it', on: { click: function () { clear(reveal); reveal.hidden = true; } } })]);
      reveal.hidden = false;
      inp.focus(); inp.select();
    }
    function load() {
      api('GET', '/v1/auth/keys').then(function (d) {
        var keys = listOf(d, 'keys');
        clear(list);
        if (!keys.length) { list.appendChild(h('p', { class: 'app-hint', text: 'No API keys yet.' })); return; }
        list.appendChild(table(['Name', 'Key', 'Created', 'Last used', ''], keys.map(function (k) {
          var rm = h('button', { type: 'button', class: 'app-btn app-btn-s app-btn-danger', text: 'Revoke',
            'aria-label': 'Revoke key ' + str(k.label || k.name), on: { click: function () {
              if (!window.confirm('Revoke “' + str(k.label || k.name) + '”? Anything using it stops working at once.')) return;
              rm.disabled = true;
              api('DELETE', '/v1/auth/keys/' + encodeURIComponent(k.id)).then(load, function (e2) { rm.disabled = false; err.textContent = e2.message; });
            } } });
          return h('tr', null, h('td', { text: str(k.label || k.name) || '—' }), h('td', { class: 'app-mono', text: str(k.prefix || k.hint || '').trim() ? str(k.prefix || k.hint) + '…' : '••••' }),
            h('td', { text: fmt(k.created_at) }), h('td', { text: (k.last_used || k.last_used_at) ? fmt(k.last_used || k.last_used_at) : 'Never' }), h('td', { class: 'app-td-a' }, rm));
        })));
      }, function (e2) { clear(list); list.appendChild(h('p', { class: 'app-err', text: e2.message })); });
    }
    add(sec, [reveal, form, err, list]);
    load();
    return sec;
  }

  function usersSection() {
    var sec = h('section', { class: 'app-sec' },
      h('h2', { class: 'app-h2', text: 'People' }),
      h('p', { class: 'app-p', text: 'Everyone here can send envelopes; each person sees only their own. Administrators can also add and remove people. Give each new person their password yourself (for example by phone).' }));
    var list = h('div', { class: 'app-list' }, h('p', { class: 'app-hint', text: 'Loading…' }));
    var nm = inputField('Name', { type: 'text', maxlength: '120', autocomplete: 'off' });
    var em = inputField('Email', { type: 'email', maxlength: '254', autocomplete: 'off' });
    var pw = inputField('Temporary password (10+ characters)', { type: 'password', minlength: '10', maxlength: '200', autocomplete: 'new-password' });
    var roleSel = h('select', { class: 'app-in', id: 'role' + Math.random().toString(36).slice(2, 7) },
      h('option', { value: 'member', text: 'Member' }), h('option', { value: 'admin', text: 'Administrator' }));
    var roleWrap = h('div', { class: 'app-field' }, h('label', { class: 'app-lbl', for: roleSel.id, text: 'Role' }), roleSel);
    var err = h('p', { class: 'app-err', role: 'alert' });
    var okEl = h('p', { class: 'app-ok', role: 'status' });
    var addB = h('button', { type: 'submit', class: 'app-btn app-btn-p', text: 'Add person' });
    var form = h('form', { class: 'app-grid-form', novalidate: true }, nm.wrap, em.wrap, pw.wrap, roleWrap, h('div', { class: 'app-field app-field-b' }, addB));
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      err.textContent = ''; okEl.textContent = '';
      var email = em.input.value.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) { err.textContent = 'Enter a valid email address.'; em.input.focus(); return; }
      if (pw.input.value.length < 10) { err.textContent = 'Use a temporary password of at least 10 characters.'; pw.input.focus(); return; }
      addB.disabled = true;
      api('POST', '/v1/auth/users', { email: email, name: nm.input.value.trim(), password: pw.input.value, role: roleSel.value }).then(function () {
        addB.disabled = false;
        okEl.textContent = email + ' was added. Share the password with them separately.';
        nm.input.value = ''; em.input.value = ''; pw.input.value = ''; roleSel.value = 'member';
        load();
      }, function (e2) { addB.disabled = false; err.textContent = e2.message; });
    });
    function load() {
      api('GET', '/v1/auth/users').then(function (d) {
        var users = listOf(d, 'users');
        clear(list);
        if (!users.length) { list.appendChild(h('p', { class: 'app-hint', text: 'No one yet.' })); return; }
        list.appendChild(table(['Name', 'Email', 'Role', 'Added', ''], users.map(function (u) {
          var self = ME && u.id === ME.id;
          var rm = self ? h('span', { class: 'app-hint', text: 'You' }) : u.disabled ? h('span', { class: 'app-hint', text: 'Removed' }) : h('button', { type: 'button', class: 'app-btn app-btn-s app-btn-danger', text: 'Remove',
            'aria-label': 'Remove ' + str(u.email), on: { click: function () {
              if (!window.confirm('Remove ' + str(u.email) + '? They can no longer sign in, and their API keys stop working. Their envelopes and audit trails are kept.')) return;
              rm.disabled = true;
              api('DELETE', '/v1/auth/users/' + encodeURIComponent(u.id)).then(load, function (e2) { rm.disabled = false; err.textContent = e2.message; });
            } } });
          return h('tr', { class: u.disabled ? 'app-tr-off' : null }, h('td', { text: str(u.name).trim() || '—' }), h('td', { text: str(u.email) }),
            h('td', { text: u.role === 'admin' ? 'Administrator' : 'Member' }), h('td', { text: fmt(u.created_at) }), h('td', { class: 'app-td-a' }, rm));
        })));
      }, function (e2) { clear(list); list.appendChild(h('p', { class: 'app-err', text: e2.message })); });
    }
    add(sec, [form, err, okEl, list]);
    load();
    return sec;
  }

  boot();
})();
