/*! Daertho E-Sign — owner app (vanilla JS, ES2019, no dependencies, no external requests).
 *
 *  Mounted full-page by app.js:
 *    window.ESign.mount(rootEl, {setTitle(str), envelopeId?, brandName?, onRoute(envelopeId|null)?})
 *    window.ESign.isDirty()  -> true while a save/upload is pending or failed
 *    window.ESign.leave()    -> Promise<boolean>: saves pending work; true when it's safe to navigate away
 *    window.ESign.unmount()
 *
 *  Contract: E-Sign owner API v1 (/v1/esign). Every HTTP call goes through request() and the
 *  EP endpoint table below, so integration fixes are one-liners.
 *
 *  Notes / decisions:
 *   - "Declined & voided" tab fetches ?status=all and filters declined|voided client-side (one request).
 *   - All mutations of one draft go through a single serial promise queue (P.queue) so uploads, recipient
 *     saves and field saves never race each other on the server.
 *   - Everything renders inside the root; all CSS lives under .es (see esign.css).
 */
(function () {
  'use strict';

  /* ================================================================== constants */
  var API_BASE = '/v1/esign';
  var VIEW_SCALE = 1.5;                       // page PNG scale used everywhere (shares the browser cache)
  var MAX_FILE = 25 * 1024 * 1024;
  var MAX_DOCS = 20;
  var DEFAULT_TITLE = 'Untitled envelope';
  var EMAIL_RE = /^[^\s@<>()",;:]+@[^\s@<>()",;:]+\.[^\s@<>()",;:]{2,}$/;
  // the server's rule for an address we email from E-Sign (plain ASCII mailbox, no quotes or encoded words)
  var MAILABLE_RE = /^[A-Za-z0-9!#$%&*+\/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&*+\/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;
  function mailable(v) { v = str(v).trim(); return v.length <= 254 && v.indexOf('=?') < 0 && MAILABLE_RE.test(v) && EMAIL_RE.test(v); }
  var MIN_FRAC = 0.02;
  // Uploads: PDF and images as before, plus word-processor files the server converts to PDF (headless LibreOffice).
  var OFFICE_EXTS = ['docx', 'doc', 'docm', 'dot', 'dotx', 'dotm', 'odt', 'ott', 'rtf'];
  var UPLOAD_EXTS = ['pdf', 'png', 'jpg', 'jpeg'].concat(OFFICE_EXTS);
  var OFFICE_MIME = /^(application\/(msword|rtf|vnd\.openxmlformats-officedocument\.wordprocessingml\.(document|template)|vnd\.ms-word\.(document|template)\.macroenabled\.12|vnd\.oasis\.opendocument\.text(-template)?)|text\/rtf)$/i;
  var UPLOAD_MIME = /^(application\/pdf|image\/png|image\/jpeg)$/i;
  var UPLOAD_ACCEPT = '.pdf,.docx,.doc,.odt,.rtf,.png,.jpg,.jpeg,application/pdf,' +
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/msword,' +
    'application/vnd.oasis.opendocument.text,application/rtf,text/rtf,image/png,image/jpeg';
  var SOURCE_LABEL = { docx: 'Word', doc: 'Word', odt: 'OpenDocument', rtf: 'RTF' };

  var COLORS = ['#5b45c9', '#b23f34', '#2f7d4f', '#a9812c', '#2b6cb0', '#b83280', '#4a5568', '#c05621'];

  var ENV_LABEL = { draft: 'Draft', sent: 'In progress', completed: 'Completed', declined: 'Declined',
    voided: 'Voided', expired: 'Expired' };
  var ENV_TONE = { draft: 'mute', sent: 'blue', completed: 'green', declined: 'red', voided: 'red', expired: 'amber' };
  var RCP_LABEL = { created: 'Not sent', pending: 'Waiting for earlier signers', sent: 'Link ready — share it',
    notified: 'Shared', viewed: 'Viewed', signed: 'Signed', declined: 'Declined', completed: 'Copy available' };
  var RCP_TONE = { created: 'mute', pending: 'mute', sent: 'amber', notified: 'blue', viewed: 'blue',
    signed: 'green', declined: 'red', completed: 'green' };
  var ROLE_LABEL = { signer: 'Needs to sign', cc: 'Receives a copy', viewer: 'Needs to view' };
  var ROLES = ['signer', 'cc', 'viewer'];

  var FIELD_TYPES = [
    { type: 'signature', label: 'Signature', short: 'Sign', w: 170, h: 42, icon: 'pen' },
    { type: 'initials', label: 'Initials', short: 'Initial', w: 60, h: 36, icon: 'initials' },
    { type: 'date_signed', label: 'Date signed', short: 'Date signed', w: 100, h: 20, icon: 'calendar' },
    { type: 'name', label: 'Full name', short: 'Full name', w: 150, h: 20, icon: 'user' },
    { type: 'email', label: 'Email', short: 'Email', w: 170, h: 20, icon: 'at' },
    { type: 'company', label: 'Company', short: 'Company', w: 150, h: 20, icon: 'building' },
    { type: 'title', label: 'Title', short: 'Title', w: 130, h: 20, icon: 'tag' },
    { type: 'text', label: 'Text', short: 'Text', w: 150, h: 20, icon: 'text' },
    { type: 'date', label: 'Date', short: 'Date', w: 100, h: 20, icon: 'calendar' },
    { type: 'checkbox', label: 'Checkbox', short: '', w: 16, h: 16, icon: 'checkbox' }
  ];
  var FT = {};
  FIELD_TYPES.forEach(function (t) { FT[t.type] = t; });

  var FILTERS = [
    { key: 'all', label: 'All', status: 'all' },
    { key: 'action', label: 'Action required', status: 'action' },
    { key: 'waiting', label: 'Waiting for others', status: 'waiting' },
    { key: 'draft', label: 'Drafts', status: 'draft' },
    { key: 'completed', label: 'Completed', status: 'completed' },
    { key: 'declined_voided', label: 'Declined & voided', status: 'all', only: ['declined', 'voided'] },
    { key: 'expired', label: 'Expired', status: 'expired' }
  ];
  var EMPTY = {
    all: ['No envelopes yet', 'Create an envelope, add your documents and recipients, then share each signing link.'],
    action: ['Nothing needs your attention', 'Envelopes with signing links ready to share will show up here.'],
    waiting: ['Not waiting on anyone', 'Envelopes you’ve shared and are waiting on will show up here.'],
    draft: ['No drafts', 'Envelopes you’re still preparing will show up here.'],
    completed: ['No completed envelopes yet', 'Once everyone has signed, the envelope lands here with its signed PDF.'],
    declined_voided: ['Nothing declined or voided', 'Envelopes that were declined by a signer or voided by you show up here.'],
    expired: ['No expired envelopes', 'Envelopes that passed their expiry date show up here.']
  };

  var EVENT_LABEL = {
    created: 'Envelope created', document_added: 'Document added', document_removed: 'Document removed',
    recipients_updated: 'Recipients updated', fields_updated: 'Fields updated', updated: 'Envelope updated',
    sent: 'Envelope sent', link_regenerated: 'Signing link regenerated', notified: 'Link marked as shared',
    viewed: 'Viewed', access_code_failed: 'Wrong access code entered', access_code_ok: 'Access code accepted',
    consented: 'Agreed to sign electronically', signed: 'Signed', viewer_acknowledged: 'Reviewed (acknowledged)',
    declined: 'Declined', routing_advanced: 'Routing advanced to next signers', completed: 'Envelope completed',
    voided: 'Envelope voided', expired: 'Envelope expired', downloaded: 'Downloaded', corrected: 'Recipient details corrected',
    email_code_sent: 'Email code sent', email_code_ok: 'Email code confirmed', email_code_failed: 'Wrong email code entered',
    sealed: 'Final PDF sealed',
    emailed: 'Emailed', email_failed: 'Email not delivered'
  };

  /* Constant SVG fragments (never contain user data). 24×24, stroke = currentColor. */
  var ICONS = {
    plus: '<path d="M12 5v14M5 12h14"/>',
    back: '<path d="M15 18l-6-6 6-6"/>',
    next: '<path d="M9 18l6-6-6-6"/>',
    up: '<path d="M18 15l-6-6-6 6"/>',
    down: '<path d="M6 9l6 6 6-6"/>',
    x: '<path d="M18 6L6 18M6 6l12 12"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="1"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
    mail: '<rect x="2" y="4" width="20" height="16" rx="1"/><path d="M22 6l-10 7L2 6"/>',
    check: '<path d="M20 6L9 17l-5-5"/>',
    refresh: '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>',
    edit: '<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
    pen: '<path d="M3 17c2.5 0 3.5-5 6-5s1.5 5 4 5 3-3 4.5-3"/><path d="M15 4l5 5M13.5 5.5l5 5"/><path d="M3 21h18"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>',
    doc: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
    shieldx: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/>',
    eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    eyeoff: '<path d="M17.9 17.9A10 10 0 0 1 12 20c-7 0-11-8-11-8a18.5 18.5 0 0 1 5.1-5.9M9.9 4.2A9 9 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.2 3.2M14.1 14.1a3 3 0 1 1-4.2-4.2M1 1l22 22"/>',
    user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    calendar: '<rect x="3" y="4" width="18" height="18" rx="1"/><path d="M16 2v4M8 2v4M3 10h18"/>',
    at: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.9 7.9"/>',
    building: '<rect x="4" y="2" width="16" height="20" rx="1"/><path d="M9 22v-4h6v4M8 6h.01M16 6h.01M12 6h.01M8 10h.01M16 10h.01M12 10h.01M8 14h.01M16 14h.01M12 14h.01"/>',
    tag: '<path d="M20.6 13.4l-7.2 7.2a2 2 0 0 1-2.8 0L2 12V2h10l8.6 8.6a2 2 0 0 1 0 2.8z"/><path d="M7 7h.01"/>',
    text: '<path d="M4 7V4h16v3M9 20h6M12 4v16"/>',
    checkbox: '<rect x="3" y="3" width="18" height="18" rx="1"/><path d="M8 12l3 3 5-6"/>',
    initials: '<path d="M2.5 19L6.5 5l4 14M4 14h5M14 5h3.5a3 3 0 0 1 0 6H14zM14 11h4.5a4 4 0 0 1 0 8H14z"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
    clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    ban: '<circle cx="12" cy="12" r="10"/><path d="M4.9 4.9l14.2 14.2"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    send: '<path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="1"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
    alert: '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    note: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    more: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    sliders: '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
    idcard: '<rect x="2" y="5" width="20" height="14" rx="1"/><circle cx="8.5" cy="11" r="2.2"/><path d="M5 16.2c.7-1.4 2-2.1 3.5-2.1s2.8.7 3.5 2.1M15 10h4.5M15 13.5h3.5"/>',
    cert: '<circle cx="12" cy="9" r="6"/><path d="M9.5 8.8l1.7 1.7 3.3-3.3"/><path d="M8.6 13.9L7 22l5-2.6 5 2.6-1.6-8.1"/>',
    zoom: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3M11 8v6M8 11h6"/>'
  };

  /* ================================================================== API (the ONLY place that talks HTTP) */
  function enc(s) { return encodeURIComponent(String(s)); }
  function envPath(eid) { return '/envelopes/' + enc(eid); }

  var EP = {
    config: function () { return request('GET', '/config'); },
    list: function (status) { return request('GET', '/envelopes?status=' + enc(status || 'all')); },
    create: function (body) { return request('POST', '/envelopes', { json: body }); },
    get: function (eid) { return request('GET', envPath(eid)); },
    patch: function (eid, body) { return request('PATCH', envPath(eid), { json: body }); },
    remove: function (eid) { return request('DELETE', envPath(eid)); },
    upload: function (eid, file, onProgress) {
      var fd = new FormData(); fd.append('file', file, file.name);
      return request('POST', envPath(eid) + '/documents', { form: fd, onProgress: onProgress });
    },
    removeDoc: function (eid, did) { return request('DELETE', envPath(eid) + '/documents/' + enc(did)); },
    orderDocs: function (eid, order) { return request('PUT', envPath(eid) + '/documents/order', { json: { order: order } }); },
    docFile: function (eid, did, which) {
      return request('GET', envPath(eid) + '/documents/' + enc(did) + '/file?which=' + enc(which || 'original'), { blob: true });
    },
    putRecipients: function (eid, list) { return request('PUT', envPath(eid) + '/recipients', { json: { recipients: list } }); },
    putFields: function (eid, list) { return request('PUT', envPath(eid) + '/fields', { json: { fields: list } }); },
    send: function (eid, notify) { return request('POST', envPath(eid) + '/send', { json: typeof notify === 'boolean' ? { notify: notify } : {} }); },
    notified: function (eid, rid) { return request('POST', envPath(eid) + '/recipients/' + enc(rid) + '/notified', { json: {} }); },
    regenerate: function (eid, rid) { return request('POST', envPath(eid) + '/recipients/' + enc(rid) + '/regenerate', { json: {} }); },
    remind: function (eid, rid) { return request('POST', envPath(eid) + '/recipients/' + enc(rid) + '/remind', { json: {} }); },
    correct: function (eid, rid, body) { return request('PATCH', envPath(eid) + '/recipients/' + enc(rid), { json: body }); },
    voidEnv: function (eid, reason) { return request('POST', envPath(eid) + '/void', { json: { reason: reason } }); },
    duplicate: function (eid) { return request('POST', envPath(eid) + '/duplicate', { json: {} }); },
    download: function (eid, kind) { return request('GET', envPath(eid) + '/download?kind=' + enc(kind || 'combined'), { blob: true }); },
    verify: function (file, onProgress) {
      var fd = new FormData(); fd.append('file', file, file.name);
      return request('POST', '/verify', { form: fd, onProgress: onProgress });
    },
    pageUrl: function (eid, did, n, scale) {
      return API_BASE + envPath(eid) + '/documents/' + enc(did) + '/pages/' + enc(n) + '.png?scale=' + (scale || VIEW_SCALE);
    },
    rootCertUrl: '/v1/sign/root.crt'          // public: this server's E-Sign root CA (PEM)
  };

  /** Core HTTP helper. opts: {json, form, blob, onProgress}. Resolves parsed JSON (or text / null),
   *  or {blob, filename, type} when opts.blob. Rejects with an Error carrying {status, detail, problems}. */
  function request(method, path, opts) {
    opts = opts || {};
    var url = API_BASE + path;
    var headers = { 'Accept': opts.blob ? '*/*' : 'application/json' };
    var body;
    if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.json); }
    else if (opts.form) body = opts.form;
    if (opts.onProgress && opts.form) return xhrRequest(method, url, headers, body, opts.onProgress);
    return fetch(url, { method: method, headers: headers, body: body, credentials: 'same-origin', cache: 'no-store' })
      .then(null, function () { throw netError(); })
      .then(function (resp) {
        if (!resp.ok) {
          return resp.text().then(function (t) { throw httpError(resp.status, parseBody(t)); },
            function () { throw httpError(resp.status, null); });
        }
        if (opts.blob) {
          return resp.blob().then(function (blob) {
            return { blob: blob, filename: filenameFrom(resp.headers.get('Content-Disposition')),
              type: resp.headers.get('Content-Type') || '' };
          });
        }
        return resp.text().then(parseBody);
      });
  }

  function xhrRequest(method, url, headers, body, onProgress) {
    return new Promise(function (resolve, reject) {
      var x = new XMLHttpRequest();
      x.open(method, url, true);
      x.withCredentials = true;
      Object.keys(headers).forEach(function (k) { x.setRequestHeader(k, headers[k]); });
      if (x.upload) {
        x.upload.onprogress = function (ev) {
          if (ev.lengthComputable && ev.total > 0) { try { onProgress(ev.loaded / ev.total); } catch (e) { /* ignore */ } }
        };
      }
      x.onload = function () {
        var data = parseBody(x.responseText);
        if (x.status >= 200 && x.status < 300) resolve(data);
        else reject(httpError(x.status, data));
      };
      x.onerror = function () { reject(netError()); };
      x.onabort = function () { reject(netError('Upload cancelled')); };
      x.ontimeout = function () { reject(netError('The request timed out')); };
      x.send(body);
    });
  }

  function parseBody(text) {
    if (text == null || text === '') return null;
    try { return JSON.parse(text); } catch (e) { return String(text); }
  }

  function netError(msg) {
    var e = new Error(msg || 'Network error — check your connection and try again.');
    e.status = 0; e.detail = e.message; e.problems = [];
    return e;
  }

  function httpError(status, data) {
    var detail = null, problems = [];
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var inner = (data.detail && typeof data.detail === 'object' && !Array.isArray(data.detail)) ? data.detail : null;
      problems = normProblems(data.problems || (inner && inner.problems));
      detail = detailText(data.detail !== undefined ? data.detail : (data.message || data.error));
    } else if (Array.isArray(data)) {
      detail = detailText(data);
    } else if (typeof data === 'string') {
      var t = data.trim();
      if (t && t.length < 300 && t.charAt(0) !== '<') detail = t;
    }
    if (!detail) detail = defaultHttpMsg(status);
    var e = new Error(detail);
    e.status = status; e.detail = detail; e.problems = problems; e.data = data;
    return e;
  }

  function detailText(x) {
    if (x == null) return null;
    if (typeof x === 'string') return x;
    if (Array.isArray(x)) {
      return x.map(function (i) {
        if (typeof i === 'string') return i;
        if (i && (i.msg || i.message)) {
          var loc = Array.isArray(i.loc) ? i.loc.filter(function (l) { return l !== 'body'; }).join('.') : '';
          return (loc ? loc + ': ' : '') + (i.msg || i.message);
        }
        try { return JSON.stringify(i); } catch (e) { return String(i); }
      }).join('; ');
    }
    if (typeof x === 'object') return detailText(x.detail || x.message || x.msg || null);
    return String(x);
  }

  function normProblems(p) {
    if (!p) return [];
    if (!Array.isArray(p)) p = [p];
    return p.map(function (i) {
      if (typeof i === 'string') return i;
      if (i && typeof i === 'object') return String(i.message || i.msg || i.detail || i.problem || i.error || JSON.stringify(i));
      return String(i);
    }).filter(Boolean);
  }

  function defaultHttpMsg(status) {
    if (status === 401) return 'Your session has expired — please sign in again.';
    if (status === 403) return 'You don’t have access to this.';
    if (status === 404) return 'Not found — it may have been deleted.';
    if (status === 409) return 'That isn’t possible in the envelope’s current state.';
    if (status === 413) return 'The file is too large (max 25 MB).';
    if (status === 415) return 'Unsupported file type — use a PDF, a Word document or an image.';
    if (status === 422) return 'Some details are invalid.';
    if (status === 429) return 'Too many requests — please wait a moment and try again.';
    if (status === 503) return 'The service is temporarily unavailable.';
    if (status >= 500) return 'Server error (' + status + '). Please try again.';
    return 'Request failed (' + status + ').';
  }

  function errMsg(e) { return (e && (e.detail || e.message)) || 'Something went wrong.'; }

  function filenameFrom(cd) {
    if (!cd) return null;
    var m = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/.exec(cd);
    if (m) { try { return decodeURIComponent(m[1].trim().replace(/^"|"$/g, '')); } catch (e) { /* fall through */ } }
    m = /filename\s*=\s*"([^"]+)"/.exec(cd) || /filename\s*=\s*([^;]+)/.exec(cd);
    return m ? m[1].trim() : null;
  }

  /* ================================================================== small utils */
  var _uid = 0;
  function uid(p) { _uid += 1; return 'es-' + (p || 'id') + '-' + _uid; }
  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function str(v) { return v == null ? '' : String(v); }
  function lc(v) { return str(v).trim().toLowerCase(); }
  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function round5(v) { return Math.round(v * 100000) / 100000; }
  function clampInt(v, a, b, dflt) { var n = parseInt(v, 10); if (isNaN(n)) n = dflt; return clamp(n, a, b); }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function randHex(n) {
    var a = new Uint8Array(Math.ceil(n / 2));
    if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(a);
    else for (var i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256);
    return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('').slice(0, n);
  }
  function colorOf(idx) { var i = parseInt(idx, 10); if (isNaN(i)) i = 0; return COLORS[((i % 8) + 8) % 8]; }
  function rgba(hex, a) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || '');
    if (!m) return 'rgba(128,128,128,' + a + ')';
    return 'rgba(' + parseInt(m[1], 16) + ',' + parseInt(m[2], 16) + ',' + parseInt(m[3], 16) + ',' + a + ')';
  }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function fmtSize(b) {
    b = Number(b) || 0;
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(b < 10240 ? 1 : 0) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  }
  function baseName(name) { return str(name).replace(/\.[a-z0-9]{2,5}$/i, ''); }
  function fileExt(name) { var m = /\.([a-z0-9]+)$/i.exec(str(name)); return m ? m[1].toLowerCase() : ''; }
  function isOfficeFile(file) { return OFFICE_EXTS.indexOf(fileExt(file && file.name)) >= 0 || OFFICE_MIME.test((file && file.type) || ''); }
  /** 'Word' / 'OpenDocument' / 'RTF' when the document was converted to PDF on upload, else ''. */
  function sourceLabel(d) { var f = d && d.source_format; return (f && SOURCE_LABEL[f]) || ''; }
  function slug(s) { return (str(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60)) || 'envelope'; }
  function firstName(n) { var s = str(n).trim(); return s.split(/\s+/)[0] || s; }
  function rName(r) { return (r && (str(r.name).trim() || str(r.email).trim())) || 'Recipient'; }
  function debounce(fn, ms) {
    var t = null;
    function d() { var a = arguments, self = this; clearTimeout(t); t = setTimeout(function () { t = null; fn.apply(self, a); }, ms); }
    d.cancel = function () { clearTimeout(t); t = null; };
    return d;
  }

  /* ---- dates (server sends UTC ISO; tolerate naive strings) */
  function parseDate(iso) {
    if (!iso) return null;
    var s = String(iso);
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
    var d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }
  var RTF = null;
  try { if (typeof Intl !== 'undefined' && Intl.RelativeTimeFormat) RTF = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }); } catch (e) { RTF = null; }
  function fmtDate(iso) {
    var d = parseDate(iso); if (!d) return '';
    try { return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); } catch (e) { return d.toDateString(); }
  }
  function fmtDateTime(iso) {
    var d = parseDate(iso); if (!d) return '';
    try { return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); } catch (e) { return d.toString(); }
  }
  function fmtFull(iso) {
    var d = parseDate(iso); if (!d) return '';
    try { return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }); } catch (e) { return d.toString(); }
  }
  function relTime(iso) {
    var d = parseDate(iso); if (!d) return '—';
    var s = (d.getTime() - Date.now()) / 1000, a = Math.abs(s);
    if (a < 45) return 'just now';
    if (!RTF) return fmtDate(iso);
    if (a < 3600) return RTF.format(Math.round(s / 60), 'minute');
    if (a < 86400) return RTF.format(Math.round(s / 3600), 'hour');
    if (a < 86400 * 7) return RTF.format(Math.round(s / 86400), 'day');
    return fmtDate(iso);
  }
  function todayISO() {
    var d = new Date();
    return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2);
  }

  /* ---- DOM builder: text always via textContent, attributes via setAttribute → no HTML injection */
  var PROP_KEYS = { checked: 1, disabled: 1, selected: 1, indeterminate: 1, multiple: 1, readOnly: 1 };
  function h(tag, props) {
    var el = document.createElement(tag), value;
    if (props) {
      Object.keys(props).forEach(function (k) {
        var v = props[k];
        if (v == null || v === false) return;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = String(v);
        else if (k === 'value') value = v;
        else if (k === 'style' && typeof v === 'object') {
          Object.keys(v).forEach(function (sk) {
            if (sk.indexOf('--') === 0) el.style.setProperty(sk, v[sk]); else el.style[sk] = v[sk];
          });
        } else if (k === 'on') Object.keys(v).forEach(function (ev) { el.addEventListener(ev, v[ev]); });
        else if (k === 'data') Object.keys(v).forEach(function (dk) { el.dataset[dk] = String(v[dk]); });
        else if (PROP_KEYS[k]) el[k] = !!v;
        else el.setAttribute(k, v === true ? '' : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    if (value !== undefined) el.value = String(value);
    return el;
  }
  function add(el, kid) {
    if (kid == null || kid === false) return;
    if (Array.isArray(kid)) { kid.forEach(function (k) { add(el, k); }); return; }
    el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  function icon(name, cls) {
    var s = h('span', { class: 'es-ic' + (cls ? ' ' + cls : ''), 'aria-hidden': 'true' });
    // constant markup from ICONS only (no user data)
    s.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" focusable="false">' + (ICONS[name] || '') + '</svg>';
    return s;
  }
  /** Button: btn(label, {icon, kind:'primary'|'danger'|'ghost'|'quiet', size:'s', title, onClick, disabled, aria}) */
  function btn(label, o) {
    o = o || {};
    var cls = 'es-btn' + (o.kind ? ' es-btn-' + o.kind : '') + (o.size === 's' ? ' es-btn-s' : '') + (o.iconOnly ? ' es-btn-i' : '') + (o.cls ? ' ' + o.cls : '');
    var b = h('button', { type: 'button', class: cls, title: o.title || (o.iconOnly ? label : null),
      'aria-label': o.iconOnly ? label : (o.ariaLabel || null), disabled: !!o.disabled });
    if (o.icon) b.appendChild(icon(o.icon));
    if (!o.iconOnly) b.appendChild(h('span', { class: 'es-btn-t', text: label }));
    if (o.onClick) b.addEventListener('click', function (e) { o.onClick(e, b); });
    if (o.aria) Object.keys(o.aria).forEach(function (k) { b.setAttribute(k, o.aria[k]); });
    return b;
  }
  function setBusy(b, on) {
    if (!b) return;
    b.disabled = !!on;
    b.classList.toggle('es-busy', !!on);
    if (on) b.setAttribute('aria-busy', 'true'); else b.removeAttribute('aria-busy');
  }
  function chip(label, tone, title) {
    return h('span', { class: 'es-chip es-t-' + (tone || 'mute'), title: title || null }, h('span', { class: 'es-dot', 'aria-hidden': 'true' }), label);
  }
  function envChip(status) { return chip(ENV_LABEL[status] || str(status) || 'Unknown', ENV_TONE[status] || 'mute'); }
  function rcpLabel(r, env) {
    if (r.status === 'signed' && r.role === 'viewer') return 'Reviewed';
    if (mailOn(env) && env.status === 'sent') {   /* envelopes we email, while in progress: what the email did */
      if (r.status === 'sent') return r.email_state === 'failed' ? 'Email failed — share the link' : (r.email_state === 'queued' && !r.email_held && cfg().email_links) ? 'Sending email…' : RCP_LABEL.sent;
      if (r.status === 'notified') return r.link_emailed_at ? 'Emailed' : 'Shared';
      if (r.status === 'pending' && cfg().email_links) return 'Emailed when it’s their turn';
    }
    return RCP_LABEL[r.status] || str(r.status) || '—';
  }
  function rcpChip(r, env) { return chip(rcpLabel(r, env), rcpTone(r, env)); }
  /** Does the server email this (sent) envelope's links? Envelopes from before emailing existed never do. */
  function mailOn(env) { return !!(env && env.mail && env.mail.on); }
  /** ...and can this server send them right now (so promising an email is true)? */
  function mailLive(env) { return mailOn(env) && cfg().email_links; }
  /** A ready link the recipient doesn't have and that isn't on its way by email: share it by hand. */
  function linkUnshared(env, r) {
    if (!mailOn(env)) return r.status === 'sent';
    return (r.status === 'sent' || r.status === 'viewed') && !r.notified_at && (r.email_state !== 'queued' || !!r.email_held || !cfg().email_links);
  }
  function rcpTone(r, env) {
    var tone = RCP_TONE[r.status] || 'mute';
    var live = mailOn(env) && env.status === 'sent';
    if (live && r.status === 'sent' && r.email_state === 'failed') tone = 'red';
    else if (live && r.status === 'sent' && r.email_state === 'queued' && !r.email_held) tone = 'blue';
    return tone;
  }
  var REMIND_GAP_MS = 10 * 60 * 1000;            // the server's REMIND_GAP: a reminder waits this long after an email
  /* the sender email last used by this account in this browser, offered (never filled in) on the next envelope */
  function senderEmailKey() { var k = str(cfg().owner_key); return k ? 'esign_sender_email_' + k : ''; }
  function rememberedSenderEmail() { try { var k = senderEmailKey(); return k ? str(localStorage.getItem(k)) : ''; } catch (e) { return ''; } }
  function rememberSenderEmail(v) {
    try { var k = senderEmailKey(); if (!k) return; if (v) localStorage.setItem(k, v); else localStorage.removeItem(k); } catch (e) { /* private mode */ }
  }
  function spinner(label) {
    return h('div', { class: 'es-loading', role: 'status' }, h('span', { class: 'es-spin', 'aria-hidden': 'true' }), h('span', { text: label || 'Loading…' }));
  }
  function emptyState(iconName, title, text, action) {
    return h('div', { class: 'es-empty' }, h('div', { class: 'es-empty-ic' }, icon(iconName)),
      h('div', { class: 'es-empty-t', text: title }), text ? h('p', { class: 'es-empty-s', text: text }) : null, action || null);
  }
  function callout(tone, iconName, title, text, extra) {
    return h('div', { class: 'es-callout es-co-' + tone, role: tone === 'red' ? 'alert' : null }, icon(iconName),
      h('div', { class: 'es-co-b' }, title ? h('div', { class: 'es-co-t', text: title }) : null, text ? h('div', { class: 'es-co-s', text: text }) : null, extra || null));
  }
  function field(labelText, control, hint, errEl) {
    var id = control.id || uid('f');
    control.id = id;
    return h('div', { class: 'es-fieldset' }, h('label', { class: 'es-lbl', for: id, text: labelText }), control,
      hint ? h('div', { class: 'es-hint', text: hint }) : null, errEl || null);
  }

  /* ================================================================== global state */
  var S = {
    root: null, opts: {}, mounted: false,
    viewEl: null, toastsEl: null, layerEl: null,
    view: null, viewOff: [], globalOff: [], modals: [], nav: 0,
    filter: 'all', search: '', listTok: 0, list: null,
    prep: null, det: null, sentBanner: null,
    cfg: null, cfgTok: 0, onCfg: null
  };

  /* ================================================================== what this server can do (GET /config, once per open) */
  var CFG_NONE = { email_codes: false, email_links: false, email_from: '', owner_key: '',
    seal: { configured: false, level: null, cert_sha256: null, tsa: [] } };
  function normCfg(c) {
    if (!c || typeof c !== 'object') return CFG_NONE;
    var s = c.seal && typeof c.seal === 'object' ? c.seal : {};
    return { email_codes: c.email_codes === true, email_links: c.email_links === true, email_from: str(c.email_from), owner_key: str(c.owner_key),
      seal: { configured: s.configured === true, level: s.level || null, cert_sha256: s.cert_sha256 || null, tsa: arr(s.tsa) } };
  }
  /** Until it arrives (or if it fails) nothing optional is assumed: no email codes, no seal. */
  function cfg() { return S.cfg || CFG_NONE; }
  /** The white-label service name ("Acme Sign"), from app.js (GET /v1/brand). */
  function B() { return str(S.opts && S.opts.brandName).trim() || 'E-Sign'; }
  function loadConfig() {
    var tok = S.cfgTok = S.cfgTok + 1;
    S.cfg = null;
    EP.config().then(normCfg, function () { return CFG_NONE; }).then(function (c) {
      if (tok !== S.cfgTok || !S.mounted) return;
      S.cfg = c;
      // re-render only what depends on it, in place
      if (S.mgrSub && S.mgrSub.isConnected) S.mgrSub.textContent = mgrSubText();
      if (S.view === 'prepare' && S.prep && S.prep.step === 2) refreshRecipMeta(S.prep);
      else if (S.view === 'prepare' && S.prep && S.prep.step === 4 && S.prep.env.email_available && c.email_links && !S.prep.ui.notifyShown) renderStep(S.prep);
      else if (S.view === 'detail' && S.det) rerenderDetail();
      if (typeof S.onCfg === 'function') S.onCfg();
    });
  }

  function listen(target, ev, fn, opt, bucket) {
    target.addEventListener(ev, fn, opt);
    (bucket || S.globalOff).push(function () { target.removeEventListener(ev, fn, opt); });
  }
  function onViewDispose(fn) { S.viewOff.push(fn); }
  function disposeView() {
    var fns = S.viewOff; S.viewOff = [];
    fns.forEach(function (f) { try { f(); } catch (e) { /* ignore */ } });
  }
  function setTitle(t) {
    try { if (S.opts && typeof S.opts.setTitle === 'function') S.opts.setTitle(t); } catch (e) { /* ignore */ }
  }
  function setView(name, render) {
    disposeView();
    S.onCfg = null;
    S.view = name;
    S.nav += 1;
    var v = S.viewEl;
    v.className = 'es-view es-v-' + name;
    v.textContent = '';
    v.scrollTop = 0;
    render(v);
  }

  /* ================================================================== toasts + dialogs */
  function toast(msg, kind, o) {
    if (!S.toastsEl) return;
    o = o || {};
    kind = kind || 'info';
    var t = h('div', { class: 'es-toast es-toast-' + kind, role: kind === 'err' ? 'alert' : null });
    t.appendChild(icon(kind === 'err' ? 'alert' : kind === 'ok' ? 'check' : kind === 'warn' ? 'alert' : 'info', 'es-toast-ic'));
    t.appendChild(h('span', { class: 'es-toast-m', text: String(msg) }));
    var timer = null;
    function dismiss() {
      clearTimeout(timer);
      t.classList.add('es-out');
      setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 180);
    }
    if (o.action) {
      t.appendChild(h('button', { type: 'button', class: 'es-toast-a', text: o.action.label,
        on: { click: function () { dismiss(); try { o.action.fn(); } catch (e) { /* ignore */ } } } }));
    }
    t.appendChild(h('button', { type: 'button', class: 'es-toast-x', 'aria-label': 'Dismiss', on: { click: dismiss } }, icon('x')));
    S.toastsEl.appendChild(t);
    while (S.toastsEl.children.length > 4) S.toastsEl.removeChild(S.toastsEl.firstChild);
    var ms = o.timeout || (kind === 'err' ? 8000 : o.action ? 7000 : 3600);
    timer = setTimeout(dismiss, ms);
    t.addEventListener('mouseenter', function () { clearTimeout(timer); });
    t.addEventListener('mouseleave', function () { clearTimeout(timer); timer = setTimeout(dismiss, 2500); });
    t.addEventListener('focusin', function () { clearTimeout(timer); });
  }

  function focusables(root) {
    return Array.prototype.filter.call(root.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'),
    function (el) { return el.offsetWidth > 0 || el.offsetHeight > 0 || el === document.activeElement; });
  }

  /** modal({title, body, actions:[{label, kind, value, onClick(m, btn) → value|false|Promise}], onClose(value), dismissable, wide, cls, initialFocus}) */
  function modal(o) {
    if (!S.layerEl) return { close: function () {}, el: null };
    var prevFocus = document.activeElement;
    var titleId = uid('mt');
    var box = h('div', { class: 'es-modal' + (o.wide ? ' es-modal-w' : '') + (o.cls ? ' ' + o.cls : ''), role: o.alert ? 'alertdialog' : 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId });
    var back = h('div', { class: 'es-backdrop' }, box);
    var done = false;
    var m = {
      el: box,
      close: function (val) {
        if (done) return;
        done = true;
        if (back.parentNode) back.parentNode.removeChild(back);
        var i = S.modals.indexOf(m); if (i >= 0) S.modals.splice(i, 1);
        if (prevFocus && prevFocus.focus && document.body.contains(prevFocus)) { try { prevFocus.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
        if (o.onClose) o.onClose(val);
      }
    };
    box.appendChild(h('div', { class: 'es-modal-h' }, h('h3', { class: 'es-modal-t', id: titleId, text: o.title || '' }),
      btn('Close', { icon: 'x', iconOnly: true, kind: 'quiet', onClick: function () { m.close(null); } })));
    var bodyEl = h('div', { class: 'es-modal-b' });
    add(bodyEl, o.body);
    box.appendChild(bodyEl);
    if (o.actions && o.actions.length) {
      var foot = h('div', { class: 'es-modal-f' });
      o.actions.forEach(function (a) {
        var b = btn(a.label, { kind: a.kind, icon: a.icon, onClick: function () {
          if (!a.onClick) { m.close(a.value); return; }
          var r = a.onClick(m, b);
          if (r && typeof r.then === 'function') {
            setBusy(b, true);
            r.then(function (v) { setBusy(b, false); if (v !== false) m.close(v); }, function () { setBusy(b, false); });
          } else if (r !== false) m.close(r);
        } });
        foot.appendChild(b);
      });
      box.appendChild(foot);
    }
    if (o.dismissable !== false) {
      back.addEventListener('mousedown', function (e) { if (e.target === back) m.close(null); });
    }
    S.layerEl.appendChild(back);
    S.modals.push(m);
    setTimeout(function () {
      var dangerous = (o.actions || []).some(function (a) { return a.kind === 'danger'; });
      var f = o.initialFocus || focusables(bodyEl)[0] ||
        (dangerous ? box.querySelector('.es-modal-f .es-btn-ghost') : box.querySelector('.es-modal-f .es-btn-primary')) || focusables(box)[0];
      if (f) { try { f.focus(); } catch (e) { /* ignore */ } }
    }, 20);
    return m;
  }

  function confirmDialog(text, o) {
    o = o || {};
    return new Promise(function (resolve) {
      var body = [];
      String(text).split('\n\n').forEach(function (para) { body.push(h('p', { class: 'es-modal-p', text: para })); });
      modal({ title: o.title || 'Please confirm', body: body, alert: true,
        actions: [{ label: o.cancelLabel || 'Cancel', kind: 'ghost', value: false },
          { label: o.okLabel || 'OK', kind: o.danger ? 'danger' : 'primary', value: true }],
        onClose: function (v) { resolve(v === true); } });
    });
  }

  /** promptDialog(label, {title, value, placeholder, required, multiline, maxLength, okLabel, danger, help}) → Promise<string|null> */
  function promptDialog(label, o) {
    o = o || {};
    return new Promise(function (resolve) {
      var inp = o.multiline
        ? h('textarea', { class: 'es-in es-ta', rows: '4', maxlength: o.maxLength ? String(o.maxLength) : null, placeholder: o.placeholder || null, value: o.value || '' })
        : h('input', { class: 'es-in', type: 'text', maxlength: o.maxLength ? String(o.maxLength) : null, placeholder: o.placeholder || null, value: o.value || '' });
      var err = h('div', { class: 'es-err', 'aria-live': 'polite' });
      var m;
      function submit() {
        var v = inp.value.trim();
        if (o.required && !v) { err.textContent = 'This is required.'; inp.setAttribute('aria-invalid', 'true'); inp.focus(); return false; }
        return v;
      }
      if (!o.multiline) inp.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); var v = submit(); if (v !== false) m.close(v); } });
      m = modal({ title: o.title || label, initialFocus: inp,
        body: [o.help ? h('p', { class: 'es-modal-p', text: o.help }) : null, field(label, inp, null, err)],
        actions: [{ label: 'Cancel', kind: 'ghost', value: null },
          { label: o.okLabel || 'OK', kind: o.danger ? 'danger' : 'primary', onClick: function () { return submit(); } }],
        onClose: function (v) { resolve(typeof v === 'string' ? v : null); } });
    });
  }

  function closeAllModals() { S.modals.slice().forEach(function (m) { m.close(null); }); }

  /* ================================================================== downloads + clipboard */
  function saveBlob(res, fallback) {
    if (!res || !res.blob) throw new Error('Empty download');
    var url = URL.createObjectURL(res.blob);
    var a = h('a', { href: url, download: res.filename || fallback, style: { display: 'none' } });
    (S.root || document.body).appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); if (a.parentNode) a.parentNode.removeChild(a); }, 5000);
  }
  function runDownload(fn, fallback, b) {
    setBusy(b, true);
    return fn().then(function (res) { saveBlob(res, fallback); }, function (err) { toast('Download failed: ' + errMsg(err), 'err'); })
      .then(function () { setBusy(b, false); });
  }
  function downloadEnvelope(env, kind, b) {
    var base = slug(env.title);
    var name = kind === 'certificate' ? base + '-certificate.pdf' : (env.status === 'completed' ? base + '-signed.pdf' : base + '-current.pdf');
    return runDownload(function () { return EP.download(env.id, kind); }, name, b);
  }
  function copyText(text, inputEl) {
    function fallback() {
      var ok = false;
      if (inputEl) { try { inputEl.focus(); inputEl.select(); ok = document.execCommand('copy'); } catch (e) { ok = false; } }
      return ok ? Promise.resolve(true) : Promise.reject(new Error('copy failed'));
    }
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).then(function () { return true; }, fallback);
    return fallback();
  }

  /* ================================================================== keyboard (capture phase on window) */
  function isTyping(t) {
    if (!t) return false;
    var tag = t.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || !!t.isContentEditable;
  }
  function consume(e) { e.preventDefault(); e.stopPropagation(); }
  function onKeyCapture(e) {
    if (!S.mounted || !S.root || !S.root.getClientRects().length) return;
    var top = S.modals[S.modals.length - 1];
    if (top) {
      if (e.key === 'Escape') { consume(e); top.close(null); return; }
      if (e.key === 'Tab') {
        var f = focusables(top.el);
        if (!f.length) { consume(e); return; }
        var first = f[0], last = f[f.length - 1];
        if (!top.el.contains(document.activeElement)) { consume(e); first.focus(); }
        else if (e.shiftKey && document.activeElement === first) { consume(e); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { consume(e); first.focus(); }
      }
      return;
    }
    if (S.view === 'prepare' && S.prep && S.prep.step === 3) editorKey(S.prep, e);
  }
  function onVisibility() {
    if (document.visibilityState === 'visible' && S.view === 'detail' && S.det) refreshDetail(false);
  }
  function preventFileDrop(e) {
    var dt = e.dataTransfer;
    if (dt && dt.types && Array.prototype.indexOf.call(dt.types, 'Files') >= 0) {
      e.preventDefault();
      if (e.type === 'dragover') dt.dropEffect = 'none';
    }
  }

  /* ================================================================== mount API */
  function mount(root, opts) {
    if (!root) throw new Error('ESign.mount: a root element is required');
    if (S.mounted) unmount();
    S.root = root; S.opts = opts || {}; S.mounted = true;
    root.classList.add('es');
    root.textContent = '';
    S.viewEl = h('div', { class: 'es-view' });
    S.toastsEl = h('div', { class: 'es-toasts', 'aria-live': 'polite', 'aria-relevant': 'additions' });
    S.layerEl = h('div', { class: 'es-layer' });
    root.appendChild(S.viewEl); root.appendChild(S.toastsEl); root.appendChild(S.layerEl);
    listen(window, 'keydown', onKeyCapture, true);
    listen(root, 'dragover', preventFileDrop);
    listen(root, 'drop', preventFileDrop);
    listen(document, 'visibilitychange', onVisibility);
    loadConfig();
    var id = S.opts.envelopeId;
    if (id === 'verify') goVerify(); else if (id) openEnvelope(String(id)); else goManage();
  }

  function unmount() {
    if (!S.mounted) return;
    var P = S.prep;
    if (P) { try { flushAll(P); } catch (e) { /* best effort */ } }
    closeAllModals();
    disposeView();
    S.globalOff.forEach(function (f) { try { f(); } catch (e) { /* ignore */ } });
    S.globalOff = [];
    if (S.root) { S.root.textContent = ''; S.root.classList.remove('es'); }
    S.root = null; S.viewEl = null; S.toastsEl = null; S.layerEl = null;
    S.prep = null; S.det = null; S.view = null; S.list = null; S.mounted = false; S.opts = {};
    S.cfg = null; S.onCfg = null; S.cfgTok += 1;
  }

  function isDirty() {
    var P = S.prep;
    if (!S.mounted || !P) return false;
    return prepDirty(P);
  }

  /* ================================================================== navigation */
  function navigate(fn) {
    var P = S.prep;
    if (S.view === 'prepare' && P) {
      return leavePrepare(P).then(function (ok) { if (ok) { S.prep = null; fn(); } });
    }
    fn();
    return Promise.resolve();
  }
  function backBtn(label, fn) {
    return btn(label, { icon: 'back', kind: 'quiet', cls: 'es-back', onClick: function () { navigate(fn); } });
  }
  /* Embedded mode (opts.onExit — a host page opening one envelope directly): a "back" that would leave
     the envelope returns to the host instead, after the same save-and-confirm as any other exit. Without
     onExit nothing changes. */
  function embedded() { return !!(S.opts && typeof S.opts.onExit === 'function'); }
  function exitToHost() { try { S.opts.onExit(); } catch (e) { /* the host handles its own errors */ } }
  function backOut() {
    return embedded() ? backBtn(S.opts.exitLabel || 'Back', exitToHost) : backBtn('Envelopes', goManage);
  }

  function openEnvelope(id) {
    S.prep = null; S.det = null;
    setView('loading', function (el) { el.appendChild(h('div', { class: 'es-page' }, spinner('Opening envelope…'))); });
    var nav = S.nav;
    EP.get(id).then(function (env) {
      if (nav !== S.nav || !S.mounted) return;
      if (!env || typeof env !== 'object' || !env.id) throw new Error('Unexpected response from the server.');
      if (env.status === 'draft') goPrepare(env); else goDetail(env);
    }).then(null, function (err) {
      if (err && err.status == null && window.console) console.error('[ESign] open failed', err);
      if (nav !== S.nav || !S.mounted) return;
      setView('error', function (el) {
        el.appendChild(h('div', { class: 'es-page' },
          h('div', { class: 'es-topbar' }, backOut()),
          emptyState('alert', 'Couldn’t open this envelope', errMsg(err),
            h('div', { class: 'es-row-gap' }, btn('Try again', { icon: 'refresh', onClick: function () { openEnvelope(id); } }),
              btn('All envelopes', { kind: 'primary', onClick: goManage })))));
      });
    });
  }

  /* ================================================================== MANAGE */
  /** Tell the host which view is showing so it can keep the URL hash in step (#envelope/<id>, #verify). */
  function route(id) {
    try { if (S.opts && typeof S.opts.onRoute === 'function') S.opts.onRoute(id); } catch (e) { /* ignore */ }
  }
  function goManage() {
    S.prep = null; S.det = null;
    route(null);
    setTitle('E-Sign');
    setView('manage', renderManage);
  }

  function mgrSubText() {
    return cfg().email_links
      ? 'Prepare documents, place signature fields and track every step. ' + B() + ' can email each recipient their own private signing link, or you can share the links yourself.'
      : 'Prepare documents, place signature fields and track every step. ' + B() + ' creates a private signing link for each recipient — you share it yourself.';
  }
  function renderManage(el) {
    var wrap = h('div', { class: 'es-page es-mgr' });
    var newB = btn('New envelope', { icon: 'plus', kind: 'primary', onClick: function (e, b) { newEnvelope(b); } });
    wrap.appendChild(h('div', { class: 'es-mgr-head' },
      h('div', { class: 'es-mgr-intro' },
        h('div', { class: 'es-kicker', text: B() }),
        h('h2', { class: 'es-h1', text: 'Envelopes' }),
        S.mgrSub = h('p', { class: 'es-sub', text: mgrSubText() })),
      h('div', { class: 'es-mgr-acts' },
        btn('Verify a document', { icon: 'shield', onClick: function () { goVerify(); } }), newB)));

    var tabs = h('div', { class: 'es-tabs', role: 'tablist', 'aria-label': 'Filter envelopes' });
    var panelId = uid('panel');
    FILTERS.forEach(function (f) {
      var on = S.filter === f.key;
      var t = h('button', { type: 'button', class: 'es-tab' + (on ? ' es-on' : ''), role: 'tab', 'aria-selected': on ? 'true' : 'false',
        'aria-controls': panelId, tabindex: on ? '0' : '-1', data: { key: f.key }, text: f.label });
      t.addEventListener('click', function () { if (S.filter !== f.key) { S.filter = f.key; selectTab(); loadList(); } });
      tabs.appendChild(t);
    });
    tabs.addEventListener('keydown', function (e) {
      var list = Array.prototype.slice.call(tabs.querySelectorAll('.es-tab'));
      var i = list.indexOf(document.activeElement);
      if (i < 0) return;
      var j = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : e.key === 'Home' ? 0 : e.key === 'End' ? list.length - 1 : null;
      if (j == null) return;
      e.preventDefault();
      j = (j + list.length) % list.length;
      list[j].focus(); list[j].click();
    });
    function selectTab() {
      Array.prototype.forEach.call(tabs.querySelectorAll('.es-tab'), function (t) {
        var on = t.dataset.key === S.filter;
        t.classList.toggle('es-on', on);
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.setAttribute('tabindex', on ? '0' : '-1');
      });
    }
    wrap.appendChild(h('div', { class: 'es-tabs-wrap' }, tabs));

    var searchIn = h('input', { class: 'es-in es-search-in', type: 'search', placeholder: 'Search by title, recipient or email', 'aria-label': 'Search envelopes', value: S.search });
    var countEl = h('span', { class: 'es-count', 'aria-live': 'polite' });
    var refreshB = btn('Refresh', { icon: 'refresh', iconOnly: true, kind: 'quiet', onClick: function () { loadList(); } });
    var doSearch = debounce(function () { S.search = searchIn.value; renderRows(); }, 150);
    searchIn.addEventListener('input', doSearch);
    wrap.appendChild(h('div', { class: 'es-toolbar' }, h('div', { class: 'es-search' }, icon('search'), searchIn), countEl, refreshB));

    var listEl = h('div', { class: 'es-list', id: panelId, role: 'tabpanel' });
    wrap.appendChild(listEl);
    el.appendChild(wrap);

    function renderRows() {
      listEl.textContent = '';
      var f = FILTERS.filter(function (x) { return x.key === S.filter; })[0] || FILTERS[0];
      if (S.list == null) return;
      var q = lc(S.search);
      var rows = S.list.filter(function (e) {
        if (!q) return true;
        var hay = [e.title].concat(arr(e.recipients).map(function (r) { return str(r.name) + ' ' + str(r.email); })).join(' ').toLowerCase();
        return hay.indexOf(q) >= 0;
      });
      countEl.textContent = S.list.length ? (q ? rows.length + ' of ' + plural(S.list.length, 'envelope') : plural(S.list.length, 'envelope')) : '';
      if (!rows.length) {
        if (q && S.list.length) {
          listEl.appendChild(emptyState('search', 'No envelopes match “' + S.search.trim() + '”', 'Try a different title, name or email.'));
        } else {
          var em = EMPTY[f.key] || EMPTY.all;
          listEl.appendChild(emptyState('doc', em[0], em[1], f.key === 'all' || f.key === 'draft'
            ? btn('New envelope', { icon: 'plus', kind: 'primary', onClick: function (e, b) { newEnvelope(b); } }) : null));
        }
        return;
      }
      listEl.appendChild(h('div', { class: 'es-lhead', 'aria-hidden': 'true' },
        h('span', { text: 'Envelope' }), h('span', { text: 'Status' }), h('span', { text: 'Recipients' }),
        h('span', { text: 'Next step' }), h('span', { text: 'Updated' }), h('span')));
      var ul = h('div', { role: 'list', class: 'es-rows' });
      rows.forEach(function (e) { ul.appendChild(envRow(e, loadList)); });
      listEl.appendChild(ul);
    }

    function loadList() {
      var f = FILTERS.filter(function (x) { return x.key === S.filter; })[0] || FILTERS[0];
      var tok = ++S.listTok;
      listEl.textContent = '';
      listEl.setAttribute('aria-busy', 'true');
      if (S.list == null || S.list.__filter !== f.key) {
        var sk = h('div', { class: 'es-skel-list', 'aria-hidden': 'true' });
        for (var i = 0; i < 4; i++) sk.appendChild(h('div', { class: 'es-skel-row' }, h('span'), h('span'), h('span')));
        listEl.appendChild(sk);
        listEl.appendChild(h('span', { class: 'es-vh', text: 'Loading envelopes…' }));
      } else renderRows();
      setBusy(refreshB, true);
      EP.list(f.status).then(function (data) {
        if (tok !== S.listTok || S.view !== 'manage') return;
        var list = arr(data && (data.envelopes || (Array.isArray(data) ? data : null)));
        if (f.only) list = list.filter(function (e) { return f.only.indexOf(e.status) >= 0; });
        list.sort(function (a, b) { return (parseDate(b.updated_at) || 0) - (parseDate(a.updated_at) || 0); });
        list.__filter = f.key;
        S.list = list;
        listEl.removeAttribute('aria-busy');
        setBusy(refreshB, false);
        renderRows();
      }, function (err) {
        if (tok !== S.listTok || S.view !== 'manage') return;
        S.list = null;
        listEl.removeAttribute('aria-busy');
        setBusy(refreshB, false);
        listEl.textContent = '';
        countEl.textContent = '';
        listEl.appendChild(emptyState('alert', 'Couldn’t load envelopes', errMsg(err), btn('Try again', { icon: 'refresh', onClick: loadList })));
      });
    }
    S.list = null;
    loadList();
  }

  function envRow(e, reload) {
    var row = h('div', { class: 'es-row', role: 'listitem' });
    var docs = typeof e.documents === 'number' ? e.documents : arr(e.documents).length;
    var title = h('button', { type: 'button', class: 'es-row-title', text: e.title || DEFAULT_TITLE,
      on: { click: function () { openEnvelope(e.id); } } });
    row.appendChild(h('div', { class: 'es-c-main' }, title,
      h('div', { class: 'es-row-meta' }, plural(docs, 'document'), ' · created ', relTime(e.created_at))));
    row.appendChild(h('div', { class: 'es-c-status' }, envChip(e.status)));

    var rc = h('div', { class: 'es-c-rcps' });
    var recips = arr(e.recipients).slice().sort(function (a, b) { return (a.routing_order || 0) - (b.routing_order || 0); });
    recips.slice(0, 4).forEach(function (r) {
      rc.appendChild(h('span', { class: 'es-rc es-t-' + rcpTone(r, e),
        title: rName(r) + (r.email ? ' <' + r.email + '>' : '') + ' — ' + (ROLE_LABEL[r.role] || r.role || '') + ' · ' + rcpLabel(r, e) },
      h('span', { class: 'es-dot', 'aria-hidden': 'true' }), h('span', { class: 'es-rc-n', text: rName(r) }),
      h('span', { class: 'es-vh', text: ': ' + rcpLabel(r, e) })));
    });
    if (recips.length > 4) rc.appendChild(h('span', { class: 'es-rc es-rc-more', text: '+' + (recips.length - 4) }));
    if (!recips.length) rc.appendChild(h('span', { class: 'es-dimtxt', text: 'No recipients yet' }));
    row.appendChild(rc);

    var signers = Number(e.signers) || 0, signed = Number(e.signed) || 0;
    var next = h('div', { class: 'es-c-next' });
    if (e.next_action) next.appendChild(h('div', { class: 'es-next' + (/^(share|couldn)/i.test(e.next_action) ? ' es-next-act' : ''), text: e.next_action }));
    if (signers > 0 && e.status !== 'draft') {
      var pct = Math.round(100 * signed / signers);
      next.appendChild(h('div', { class: 'es-prog' }, h('span', { class: 'es-prog-bar', 'aria-hidden': 'true' }, h('span', { style: { width: pct + '%' } })),
        h('span', { class: 'es-prog-t', text: signed + '/' + signers + ' signed' })));
    }
    row.appendChild(next);
    row.appendChild(h('div', { class: 'es-c-upd', title: fmtDateTime(e.updated_at) }, relTime(e.updated_at)));

    var acts = h('div', { class: 'es-c-acts' });
    acts.appendChild(btn('Open', { size: 's', onClick: function () { openEnvelope(e.id); } }));
    if (e.status === 'completed') {
      acts.appendChild(btn('Download', { size: 's', icon: 'download', iconOnly: true, kind: 'quiet', title: 'Download signed PDF',
        onClick: function (ev, b) { downloadEnvelope(e, 'combined', b); } }));
    }
    acts.appendChild(btn('Duplicate', { size: 's', icon: 'copy', iconOnly: true, kind: 'quiet', title: 'Duplicate as a new draft',
      onClick: function (ev, b) { duplicateEnvelope(e.id, b); } }));
    if (e.status === 'sent') {
      acts.appendChild(btn('Void', { size: 's', icon: 'ban', iconOnly: true, kind: 'quiet', cls: 'es-danger-q', title: 'Void envelope',
        onClick: function (ev, b) { voidEnvelope(e, b).then(function (env) { if (env) reload(); }); } }));
    }
    if (e.status === 'draft') {
      acts.appendChild(btn('Delete', { size: 's', icon: 'trash', iconOnly: true, kind: 'quiet', cls: 'es-danger-q', title: 'Delete draft',
        onClick: function (ev, b) { deleteDraft(e, b).then(function (ok) { if (ok) reload(); }); } }));
    }
    row.appendChild(acts);
    row.addEventListener('click', function (ev) {
      if (ev.target.closest('button, a, input, select, textarea')) return;
      var sel = window.getSelection && window.getSelection();
      if (sel && String(sel).length) return;
      openEnvelope(e.id);
    });
    return row;
  }

  function newEnvelope(b) {
    setBusy(b, true);
    EP.create({ title: DEFAULT_TITLE, signing_order: 'parallel' }).then(function (env) {
      setBusy(b, false);
      if (!env || !env.id) throw new Error('Unexpected response from the server.');
      goPrepare(env, 1);
    }).then(null, function (err) { setBusy(b, false); toast('Couldn’t create an envelope: ' + errMsg(err), 'err'); });
  }
  function duplicateEnvelope(eid, b) {
    setBusy(b, true);
    return EP.duplicate(eid).then(function (env) {
      setBusy(b, false);
      if (!env || !env.id) throw new Error('Unexpected response from the server.');
      toast('Duplicated — this is a new draft.', 'ok');
      S.prep = null; S.det = null;
      goPrepare(env);
    }).then(null, function (err) { setBusy(b, false); toast('Couldn’t duplicate: ' + errMsg(err), 'err'); });
  }
  function deleteDraft(e, b) {
    return confirmDialog('Delete the draft “' + (e.title || DEFAULT_TITLE) + '”? Its documents, recipients and fields will be removed. This can’t be undone.',
      { title: 'Delete draft', okLabel: 'Delete draft', danger: true }).then(function (ok) {
      if (!ok) return false;
      setBusy(b, true);
      return EP.remove(e.id).then(function () { setBusy(b, false); toast('Draft deleted.', 'ok'); return true; },
        function (err) { setBusy(b, false); toast('Couldn’t delete: ' + errMsg(err), 'err'); return false; });
    });
  }
  function voidEnvelope(e, b) {
    return promptDialog('Reason for voiding', { title: 'Void “' + (e.title || DEFAULT_TITLE) + '”', required: true, multiline: true, maxLength: 500,
      help: 'Voiding cancels the envelope: every signing link stops working and no one can sign. The reason is recorded in the audit trail.',
      okLabel: 'Void envelope', danger: true }).then(function (reason) {
      if (reason == null) return null;
      setBusy(b, true);
      return EP.voidEnv(e.id, reason).then(function (env) { setBusy(b, false); toast('Envelope voided.', 'ok'); return env || true; },
        function (err) { setBusy(b, false); toast('Couldn’t void: ' + errMsg(err), 'err'); return null; });
    });
  }

  /* ================================================================== PREPARE (draft wizard) */
  var STEPS = [
    { n: 1, label: 'Documents' }, { n: 2, label: 'Recipients' }, { n: 3, label: 'Place fields' }, { n: 4, label: 'Review & send' }
  ];

  function fromServerRecipient(r, i) {
    return {
      _k: uid('rk'), id: r.id || null, name: str(r.name), email: str(r.email),
      role: ROLES.indexOf(r.role) >= 0 ? r.role : 'signer', routing_order: clampInt(r.routing_order, 1, 99, 1),
      note: str(r.note), color: r.color != null ? r.color : i, access_code_set: !!r.access_code_set,
      email_code: !!r.email_code, ecSaved: !!r.email_code,   // what the owner wants / what the server last confirmed
      codeAction: null, code: '', open: false, touched: {}, status: r.status || 'created'
    };
  }
  function normField(f) {
    return {
      id: f.id || ('fld_' + randHex(10)), recipient_id: f.recipient_id, document_id: f.document_id,
      page: clampInt(f.page, 1, 100000, 1), type: FT[f.type] ? f.type : 'text',
      x: clamp(Number(f.x) || 0, 0, 1), y: clamp(Number(f.y) || 0, 0, 1),
      w: clamp(Number(f.w) || 0.1, MIN_FRAC, 1), h: clamp(Number(f.h) || 0.03, MIN_FRAC / 2, 1),
      required: f.required == null ? f.type !== 'checkbox' : !!f.required, label: f.label == null ? null : str(f.label)
    };
  }
  function normDocs(docs) {
    return arr(docs).slice().sort(function (a, b) { return (a.order || 0) - (b.order || 0); });
  }
  function docPages(d) {
    var pages = arr(d && d.pages);
    var n = (d && d.page_count) || pages.length || 1;
    var out = [];
    for (var i = 0; i < n; i++) {
      var p = pages[i] || pages[0] || {};
      out.push({ w: Number(p.w) > 0 ? Number(p.w) : 612, h: Number(p.h) > 0 ? Number(p.h) : 792 });
    }
    return out;
  }

  function goPrepare(env, step) {
    S.det = null;
    route(env.id);
    var recips = arr(env.recipients).map(fromServerRecipient);
    var orders = {};
    recips.forEach(function (r) { orders[r.routing_order] = 1; });
    var P = {
      eid: env.id, env: env, recips: recips, fields: arr(env.fields).map(normField),
      queue: Promise.resolve(), uploading: 0, uploads: [], fieldsVer: 0, sel: null, activeSigner: null,
      zoom: 'fit', sendProblems: null, ui: {}, stepOff: [], navBusy: false,
      sequential: env.signing_order === 'sequential' || Object.keys(orders).length > 1
    };
    P.env.documents = normDocs(env.documents);
    if (!step) {
      if (!P.env.documents.length) step = 1;
      else if (!recips.length) step = 2;
      else if (!P.fields.length) step = 3;
      else step = 4;
    }
    P.step = step;
    P.savers = {
      meta: makeSaver(P, 'details', saveMeta, 700),
      recips: makeSaver(P, 'recipients', saveRecips, 600),
      fields: makeSaver(P, 'fields', saveFields, 800)
    };
    S.prep = P;
    setTitle('E-Sign · ' + (env.title || DEFAULT_TITLE));
    setView('prepare', function (el) { renderPrepare(P, el); });
  }

  /* ---- serial mutation queue + savers */
  function enqueue(P, fn) {
    P.queue = P.queue.then(fn, fn).then(null, function () { /* keep the chain alive */ });
    return P.queue;
  }
  function makeSaver(P, name, run, delay) {
    var s = { name: name, dirty: false, inflight: false, failed: false, blocked: null, timer: null, err: null };
    s.schedule = function (ms) {
      s.dirty = true; s.failed = false;
      if (s.timer) clearTimeout(s.timer);
      s.timer = setTimeout(s.flush, ms == null ? delay : ms);
      saveIndicator(P);
    };
    s.flush = function () {
      if (s.timer) { clearTimeout(s.timer); s.timer = null; }
      if (!s.dirty) return P.queue;
      return enqueue(P, function () {
        if (!s.dirty) return null;
        s.dirty = false; s.inflight = true; s.blocked = null;
        saveIndicator(P);
        var r;
        try { r = run(P); } catch (e) { r = Promise.reject(e); }
        return Promise.resolve(r).then(function (res) {
          s.inflight = false;
          if (res && res.blocked) { s.blocked = res.blocked; s.dirty = true; } else { s.failed = false; s.err = null; }
        }, function (err) {
          s.inflight = false; s.failed = true; s.dirty = true; s.err = err;
          if (P === S.prep) toast('Couldn’t save ' + name + ': ' + errMsg(err), 'err', { action: { label: 'Retry', fn: function () { s.flush(); } } });
        }).then(function () { saveIndicator(P); });
      });
    };
    return s;
  }
  function flushAll(P) {
    P.savers.meta.flush();
    P.savers.fields.flush();
    P.savers.recips.flush();   // fields first: a role change may need its fields removed before the role is saved
    return P.queue;
  }
  function prepDirty(P) {
    if (P.uploading > 0) return true;
    return Object.keys(P.savers).some(function (k) { var s = P.savers[k]; return s.dirty || s.inflight || s.failed || !!s.timer; });
  }
  function leavePrepare(P) {
    return flushAll(P).then(function () {
      if (!prepDirty(P)) return true;
      var blocked = P.savers.recips.blocked || P.savers.meta.blocked;
      return confirmDialog((blocked ? blocked + '. ' : 'Some changes couldn’t be saved. ') + 'Leave this envelope anyway? Unsaved changes will be lost.',
        { title: 'Unsaved changes', okLabel: 'Leave anyway', danger: true });
    });
  }
  function saveIndicator(P) {
    var el = P.ui.saveEl;
    if (!el) return;
    var sv = P.savers, keys = Object.keys(sv);
    var failed = keys.some(function (k) { return sv[k].failed; });
    var blocked = keys.map(function (k) { return sv[k].blocked; }).filter(Boolean)[0];
    var busy = P.uploading > 0 || keys.some(function (k) { return sv[k].inflight; });
    var pending = keys.some(function (k) { return sv[k].dirty || sv[k].timer; });
    el.textContent = '';
    el.className = 'es-save';
    if (failed) {
      el.classList.add('es-save-err');
      el.appendChild(icon('alert'));
      el.appendChild(h('span', { text: 'Save failed' }));
      el.appendChild(h('button', { type: 'button', class: 'es-linkbtn', text: 'Retry', on: { click: function () { flushAll(P); } } }));
    } else if (busy) {
      el.classList.add('es-save-busy');
      el.appendChild(h('span', { class: 'es-spin es-spin-s', 'aria-hidden': 'true' }));
      var converting = P.uploads.some(function (u) { return u.status === 'uploading' && u.converting; });
      el.appendChild(h('span', { text: P.uploading > 0 ? (converting ? 'Converting…' : 'Uploading…') : 'Saving…' }));
    } else if (blocked) {
      el.classList.add('es-save-warn');
      el.appendChild(icon('alert'));
      el.appendChild(h('span', { text: 'Not saved — ' + blocked.charAt(0).toLowerCase() + blocked.slice(1) }));
    } else if (pending) {
      el.classList.add('es-save-pend');
      el.appendChild(h('span', { text: 'Unsaved changes' }));
    } else {
      el.appendChild(icon('check'));
      el.appendChild(h('span', { text: 'All changes saved' }));
    }
  }

  function saveMeta(P) {
    var t = str(P.env.title).trim();
    if (!t) return { blocked: 'Add a subject' };
    var body = { title: t.slice(0, 200), message: str(P.env.message).slice(0, 2000),
      expires_at: P.env.expires_at || null, signing_order: P.sequential ? 'sequential' : 'parallel' };
    var sn = str(P.env.sender_name).trim();
    if (sn) body.sender_name = sn.slice(0, 120);
    var se = str(P.env.sender_email).trim();
    if (se && !mailable(se)) {
      if (willEmail(P)) return { blocked: 'Fix your email address' };
    } else if (P.env.sender_email != null) body.sender_email = se;
    return EP.patch(P.eid, body).then(function (env) {
      if (env && typeof env === 'object' && env.id) {
        P.env.updated_at = env.updated_at;
        if (body.sender_email) rememberSenderEmail(body.sender_email);
        if (!sn && env.sender_name) {
          P.env.sender_name = env.sender_name;
          if (P.ui.senderIn && document.activeElement !== P.ui.senderIn) P.ui.senderIn.value = env.sender_name;
        }
      }
    });
  }

  function isBlankNew(r) { return !r.id && !r.name.trim() && !r.email.trim(); }
  function rowErrors(r) {
    var e = {}, n = r.name.trim(), m = r.email.trim();
    if (!n) e.name = 'Name is required';
    else if (n.length > 120) e.name = 'Use at most 120 characters';
    if (!m) e.email = 'Email is required';
    else if (m.length > 200 || !EMAIL_RE.test(m)) e.email = 'Enter a valid email address';
    return e;
  }
  function hasErrors(r) { var e = rowErrors(r); return !!(e.name || e.email); }

  function saveRecips(P) {
    var rows = P.recips.filter(function (r) { return !isBlankNew(r); });
    var bad = rows.filter(hasErrors);
    if (bad.length) {
      bad.forEach(function (r) { r.touched = { name: true, email: true }; });
      refreshRecipErrors(P);
      return { blocked: 'Fix recipient details to save' };
    }
    var sent = rows.map(function (r) { return { row: r, action: r.codeAction, code: r.code }; });
    var payload = sent.map(function (o) {
      var r = o.row;
      var p = { name: r.name.trim(), email: r.email.trim(), role: r.role,
        routing_order: P.sequential ? clampInt(r.routing_order, 1, 99, 1) : 1,
        note: r.note.trim() ? r.note.trim().slice(0, 1000) : null };
      if (r.id) p.id = r.id;
      if (o.action === 'set' && o.code) p.access_code = o.code;
      else if (o.action === 'clear') p.access_code = '';
      // switching it on needs a mail server, so 'on' is only sent when it changes (left out, the server keeps it)
      if (!r.email_code) p.email_code = false;
      else if (!r.ecSaved) p.email_code = true;
      return p;
    });
    return EP.putRecipients(P.eid, payload).then(function (env) {
      var list = env && Array.isArray(env.recipients) ? env.recipients : null;
      if (!list) return;
      matchRecipients(sent.map(function (o) { return o.row; }), list);
      sent.forEach(function (o) {
        var r = o.row;
        if (o.action === 'set' && r.codeAction === 'set' && r.code === o.code) {
          r.codeAction = null; r.code = '';
          if (r._ui && r._ui.codeIn && document.activeElement !== r._ui.codeIn) r._ui.codeIn.value = '';
        } else if (o.action === 'clear' && r.codeAction === 'clear') r.codeAction = null;
      });
      P.env.recipients = list;
      var ids = {};
      list.forEach(function (r) { ids[r.id] = 1; });
      var before = P.fields.length;
      P.fields = P.fields.filter(function (f) { return ids[f.recipient_id]; });
      if (P.fields.length !== before && P.step === 3) rebuildFieldEls(P);
      refreshRecipMeta(P);
    });
  }
  function matchRecipients(rows, list) {
    var claimed = {};
    function apply(r, s) {
      claimed[s.id] = 1; r.id = s.id;
      if (s.color != null) r.color = s.color;
      r.access_code_set = !!s.access_code_set;
      r.ecSaved = !!s.email_code;
      r.status = s.status || r.status;
    }
    rows.forEach(function (r) {
      if (!r.id) return;
      var s = list.filter(function (x) { return x.id === r.id; })[0];
      if (s) apply(r, s);
    });
    rows.forEach(function (r) {
      if (r.id && claimed[r.id]) return;
      var cand = list.filter(function (x) { return !claimed[x.id]; });
      var s = cand.filter(function (x) { return lc(x.email) === lc(r.email) && lc(x.name) === lc(r.name); })[0] ||
        cand.filter(function (x) { return lc(x.email) === lc(r.email); })[0];
      if (s) apply(r, s);
    });
  }

  function saveFields(P) {
    var ver = P.fieldsVer;
    var payload = P.fields.map(function (f) {
      return { id: f.id, recipient_id: f.recipient_id, document_id: f.document_id, page: f.page, type: f.type,
        x: round5(f.x), y: round5(f.y), w: round5(f.w), h: round5(f.h), required: !!f.required,
        label: f.label && f.label.trim() ? f.label.trim().slice(0, 80) : null };
    });
    return EP.putFields(P.eid, payload).then(function (env) {
      if (!env || !Array.isArray(env.fields) || ver !== P.fieldsVer) return;
      var nf = env.fields.map(normField);
      var oldIds = P.fields.map(function (f) { return f.id; }).join(',');
      var newIds = nf.map(function (f) { return f.id; }).join(',');
      if (oldIds === newIds) return;
      if (P.sel) {
        var idx = P.fields.map(function (f) { return f.id; }).indexOf(P.sel);
        P.sel = (nf.length === P.fields.length && idx >= 0) ? nf[idx].id : null;
      }
      P.fields = nf;
      if (P.step === 3) rebuildFieldEls(P);
    });
  }

  /* ---- wizard shell */
  function renderPrepare(P, el) {
    var shell = h('div', { class: 'es-wz' });
    P.ui.titleEl = h('h2', { class: 'es-wz-title', text: P.env.title || DEFAULT_TITLE });
    P.ui.saveEl = h('div', { class: 'es-save', role: 'status', 'aria-live': 'polite' });
    var discard = btn('Discard draft', { icon: 'trash', kind: 'quiet', size: 's', cls: 'es-danger-q', onClick: function (e, b) {
      deleteDraft(P.env, b).then(function (ok) { if (ok) { S.prep = null; goManage(); } });
    } });
    var top = h('div', { class: 'es-wz-top' }, backOut(),
      h('div', { class: 'es-wz-tt' }, h('div', { class: 'es-kicker', text: 'Draft envelope' }), P.ui.titleEl),
      P.ui.saveEl, discard);
    P.ui.stepsEl = h('ol', { class: 'es-steps', 'aria-label': 'Envelope setup steps' });
    var head = h('header', { class: 'es-wz-head' }, top, P.ui.stepsEl);
    P.ui.body = h('div', { class: 'es-wz-body' });
    P.ui.foot = h('footer', { class: 'es-wz-foot' });
    shell.appendChild(head); shell.appendChild(P.ui.body); shell.appendChild(P.ui.foot);
    el.appendChild(shell);
    saveIndicator(P);
    onViewDispose(function () { disposeStep(P); });
    renderStep(P);
  }
  function setWizardTitle(P) {
    var t = str(P.env.title).trim() || DEFAULT_TITLE;
    if (P.ui.titleEl) P.ui.titleEl.textContent = t;
    setTitle('E-Sign · ' + t);
  }
  function stepDone(P, n) {
    if (n === 1) return P.env.documents.length > 0;
    if (n === 2) return P.recips.some(function (r) { return r.id && r.role === 'signer'; }) && !P.recips.some(function (r) { return !isBlankNew(r) && hasErrors(r); });
    if (n === 3) {
      var signers = P.recips.filter(function (r) { return r.id && r.role === 'signer'; });
      return signers.length > 0 && signers.every(function (s) { return P.fields.some(function (f) { return f.recipient_id === s.id; }); });
    }
    return false;
  }
  function renderSteps(P) {
    var ol = P.ui.stepsEl;
    ol.textContent = '';
    STEPS.forEach(function (s) {
      var cur = P.step === s.n, done = !cur && stepDone(P, s.n);
      var b = h('button', { type: 'button', class: 'es-step' + (cur ? ' es-cur' : '') + (done ? ' es-done' : ''), 'aria-current': cur ? 'step' : null,
        on: { click: function () { goStep(P, s.n); } } },
      h('span', { class: 'es-step-n', 'aria-hidden': 'true' }, done ? icon('check') : String(s.n)),
      h('span', { class: 'es-step-l', text: s.label }),
      done ? h('span', { class: 'es-vh', text: ' (complete)' }) : null);
      ol.appendChild(h('li', null, b));
    });
  }
  function disposeStep(P) {
    var fns = P.stepOff; P.stepOff = [];
    fns.forEach(function (f) { try { f(); } catch (e) { /* ignore */ } });
    P.ed = null;
  }
  function goStep(P, n) {
    if (P.navBusy || n === P.step) return;
    var from = P.step;
    P.navBusy = true;
    var wait;
    if (from === 2 || n === 3 || n === 4) { P.savers.recips.flush(); }
    if (from === 3) P.savers.fields.flush();
    if (from === 4) P.savers.meta.flush();
    wait = (from === 2 || n === 3) ? P.queue : Promise.resolve();
    var slow = setTimeout(function () {
      if (P.ui.body) { P.ui.body.classList.add('es-waiting'); P.ui.body.setAttribute('aria-busy', 'true'); }
    }, 250);
    wait.then(function () {
      clearTimeout(slow);
      if (P.ui.body) { P.ui.body.classList.remove('es-waiting'); P.ui.body.removeAttribute('aria-busy'); }
      P.navBusy = false;
      if (S.prep !== P) return;
      if (from === 2 && P.savers.recips.blocked) toast('Some recipients have missing or invalid details and weren’t saved.', 'warn');
      P.step = n;
      renderStep(P);
    });
  }
  function renderStep(P) {
    disposeStep(P);
    renderSteps(P);
    var body = P.ui.body;
    body.textContent = '';
    body.className = 'es-wz-body es-wz-s' + P.step;
    body.scrollTop = 0;
    if (P.step === 1) renderDocsStep(P, body);
    else if (P.step === 2) renderRecipStep(P, body);
    else if (P.step === 3) renderFieldsStep(P, body);
    else renderReviewStep(P, body);
    renderFoot(P);
  }
  function renderFoot(P) {
    var f = P.ui.foot;
    f.textContent = '';
    if (embedded() && P.step < 4) {             // embedded: before Review & send, Back returns to the host
      f.appendChild(btn(S.opts.exitLabel || 'Back', { icon: 'back', kind: 'ghost', onClick: function () { navigate(exitToHost); } }));
    } else if (P.step > 1) f.appendChild(btn('Back', { icon: 'back', kind: 'ghost', onClick: function () { goStep(P, P.step - 1); } }));
    f.appendChild(h('div', { class: 'es-grow' }));
    if (P.step < 4) {
      f.appendChild(btn('Next: ' + STEPS[P.step].label, { kind: 'primary', cls: 'es-btn-next', onClick: function () { goStep(P, P.step + 1); } }));
    } else {
      var issues = computeIssues(P);
      P.ui.sendBtn = btn('Send envelope', { icon: 'send', kind: 'primary', disabled: issues.errors.length > 0,
        onClick: function (e, b) { sendEnvelope(P, b); } });
      f.appendChild(P.ui.sendBtn);
    }
  }

  /* ---- Step 1: documents */
  function renderDocsStep(P, body) {
    var pane = h('div', { class: 'es-pane es-narrow' });
    pane.appendChild(h('div', { class: 'es-pane-head' }, h('h3', { class: 'es-h3', text: 'Add documents' }),
      h('p', { class: 'es-sub', text: 'PDF, Word or image · up to 25 MB each · up to 20 documents. Word (.docx, .doc), OpenDocument (.odt) and RTF files are converted to PDF; images become a one-page PDF.' })));
    var input = h('input', { type: 'file', multiple: true, accept: UPLOAD_ACCEPT, class: 'es-vh', tabindex: '-1', 'aria-hidden': 'true' });
    input.addEventListener('change', function () { handleFiles(P, input.files); input.value = ''; });
    var choose = btn('Choose files', { icon: 'upload', kind: 'primary', onClick: function () { input.click(); } });
    var zone = h('div', { class: 'es-drop' }, h('div', { class: 'es-drop-ic' }, icon('upload')),
      h('div', { class: 'es-drop-t', text: 'Drag & drop files here' }), h('div', { class: 'es-drop-s', text: 'or' }), choose, input);
    var depth = 0;
    zone.addEventListener('dragenter', function (e) { e.preventDefault(); depth++; zone.classList.add('es-over'); });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); e.stopPropagation(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'; });
    zone.addEventListener('dragleave', function () { depth = Math.max(0, depth - 1); if (!depth) zone.classList.remove('es-over'); });
    zone.addEventListener('drop', function (e) {
      e.preventDefault(); e.stopPropagation(); depth = 0; zone.classList.remove('es-over');
      if (e.dataTransfer && e.dataTransfer.files) handleFiles(P, e.dataTransfer.files);
    });
    pane.appendChild(zone);
    P.ui.uploadsEl = h('div', { class: 'es-uploads', 'aria-live': 'polite' });
    pane.appendChild(P.ui.uploadsEl);
    P.ui.docsEl = h('div', { class: 'es-docs' });
    pane.appendChild(P.ui.docsEl);
    body.appendChild(pane);
    P.stepOff.push(function () { P.ui.uploadsEl = null; P.ui.docsEl = null; });
    renderUploads(P);
    renderDocList(P);
  }

  function handleFiles(P, files) {
    var list = Array.prototype.slice.call(files || []);
    if (!list.length) return;
    var count = P.env.documents.length + P.uploads.filter(function (u) { return u.status === 'queued' || u.status === 'uploading'; }).length;
    var tooMany = false;
    list.forEach(function (file) {
      var okType = UPLOAD_EXTS.indexOf(fileExt(file.name)) >= 0 || UPLOAD_MIME.test(file.type || '') || isOfficeFile(file);
      if (!okType) { toast('“' + file.name + '” isn’t a PDF, Word document or image (PNG/JPEG).', 'err'); return; }
      if (file.size > MAX_FILE) { toast('“' + file.name + '” is ' + fmtSize(file.size) + ' — the limit is 25 MB.', 'err'); return; }
      if (file.size === 0) { toast('“' + file.name + '” is empty.', 'err'); return; }
      if (count >= MAX_DOCS) { tooMany = true; return; }
      count++;
      var u = { id: uid('up'), file: file, name: file.name, size: file.size, status: 'queued', pct: 0, err: null,
        office: isOfficeFile(file), converting: false };
      P.uploads.push(u);
      P.uploading++;
      saveIndicator(P);
      enqueue(P, function () { return doUpload(P, u); });
    });
    if (tooMany) toast('An envelope can hold up to ' + MAX_DOCS + ' documents.', 'err');
    renderUploads(P);
  }

  function doUpload(P, u) {
    if (S.prep !== P && !S.mounted) { P.uploading--; return null; }
    u.status = 'uploading';
    u.converting = false;
    renderUploads(P);
    return EP.upload(P.eid, u.file, function (pct) {
      u.pct = pct;
      if (u._bar) u._bar.style.width = Math.round(pct * 100) + '%';
      if (u._pct) u._pct.textContent = upLabel(u);
      if (pct >= 0.999 && u.office && !u.converting) {
        // bytes are up; the server is now converting the Word file to PDF (can take several seconds)
        u.converting = true;
        if (u._barEl) { u._barEl.classList.add('es-conv'); u._barEl.setAttribute('aria-label', 'Converting ' + u.name + ' to PDF'); u._barEl.removeAttribute('aria-valuenow'); }
        if (u._pct) u._pct.textContent = upLabel(u);
        saveIndicator(P);
      }
    }).then(function (doc) {
      P.uploading--;
      u.status = 'done';
      var p = (doc && doc.id) ? Promise.resolve(doc) : EP.get(P.eid).then(function (env) { P.env.documents = normDocs(env && env.documents); return null; });
      return p.then(function (d) {
        if (d) {
          P.env.documents = P.env.documents.filter(function (x) { return x.id !== d.id; });
          P.env.documents.push(d);
        }
        P.uploads = P.uploads.filter(function (x) { return x !== u; });
        if ((!str(P.env.title).trim() || P.env.title === DEFAULT_TITLE) && P.env.documents.length) {
          P.env.title = baseName(P.env.documents[0].name).slice(0, 200) || DEFAULT_TITLE;
          setWizardTitle(P);
          P.savers.meta.schedule(300);
        }
        saveIndicator(P);
        renderUploads(P);
        renderDocList(P);
        renderSteps(P);
      });
    }, function (err) {
      P.uploading--;
      u.status = 'error';
      u.converting = false;
      u.err = errMsg(err);
      saveIndicator(P);
      renderUploads(P);
      toast('Couldn’t upload “' + u.name + '”: ' + u.err, 'err');
    });
  }

  function upLabel(u) {
    if (u.status === 'queued') return 'Waiting…';
    if (u.status === 'error') return '';
    if (u.pct >= 0.999) return u.office ? 'Converting…' : 'Processing…';
    return Math.round(u.pct * 100) + '%';
  }

  function renderUploads(P) {
    var el = P.ui.uploadsEl;
    if (!el) return;
    el.textContent = '';
    P.uploads.forEach(function (u) {
      var item = h('div', { class: 'es-up es-up-' + u.status });
      item.appendChild(icon(u.status === 'error' ? 'alert' : 'doc'));
      var info = h('div', { class: 'es-up-i' }, h('div', { class: 'es-up-n', text: u.name }));
      if (u.status === 'error') {
        info.appendChild(h('div', { class: 'es-err', text: u.err || 'Upload failed' }));
      } else {
        u._bar = h('span', { style: { width: Math.round(u.pct * 100) + '%' } });
        var conv = u.status === 'uploading' && u.converting;
        u._barEl = h('div', { class: 'es-up-bar' + (u.status === 'queued' ? ' es-q' : '') + (conv ? ' es-conv' : ''), role: 'progressbar',
          'aria-label': (conv ? 'Converting ' : 'Uploading ') + u.name + (conv ? ' to PDF' : ''),
          'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': conv ? null : String(Math.round(u.pct * 100)) }, u._bar);
        info.appendChild(u._barEl);
        if (u.office && u.status !== 'error') info.appendChild(h('div', { class: 'es-hint es-up-h', text: 'Converted to PDF on upload — this can take a few seconds.' }));
      }
      item.appendChild(info);
      u._pct = h('span', { class: 'es-up-p', text: upLabel(u) });
      item.appendChild(u._pct);
      if (u.status === 'error') {
        item.appendChild(btn('Retry', { size: 's', onClick: function () {
          u.status = 'queued'; u.pct = 0; u.err = null; P.uploading++; saveIndicator(P); renderUploads(P);
          enqueue(P, function () { return doUpload(P, u); });
        } }));
        item.appendChild(btn('Dismiss', { size: 's', icon: 'x', iconOnly: true, kind: 'quiet', onClick: function () {
          P.uploads = P.uploads.filter(function (x) { return x !== u; }); renderUploads(P);
        } }));
      }
      el.appendChild(item);
    });
  }

  function renderDocList(P) {
    var el = P.ui.docsEl;
    if (!el) return;
    el.textContent = '';
    var docs = P.env.documents;
    if (!docs.length) {
      if (!P.uploads.length) el.appendChild(h('p', { class: 'es-dimtxt es-center', text: 'No documents yet. Add the files people need to sign.' }));
      return;
    }
    var totalPages = docs.reduce(function (a, d) { return a + docPages(d).length; }, 0);
    el.appendChild(h('div', { class: 'es-sec-h' }, h('span', { class: 'es-lbl', text: plural(docs.length, 'document') + ' · ' + plural(totalPages, 'page') }),
      docs.length > 1 ? h('span', { class: 'es-hint', text: 'Recipients see the documents in this order.' }) : null));
    var ul = h('ol', { class: 'es-doclist' });
    docs.forEach(function (d, i) {
      var pg = docPages(d)[0];
      var thumb = h('div', { class: 'es-thumb', style: { aspectRatio: pg.w + ' / ' + pg.h } },
        pageImg(EP.pageUrl(P.eid, d.id, 1, VIEW_SCALE), (d.name || 'Document') + ', page 1'));
      var up = btn('Move up', { icon: 'up', iconOnly: true, kind: 'quiet', size: 's', disabled: i === 0, onClick: function () { moveDoc(P, i, -1); } });
      var dn = btn('Move down', { icon: 'down', iconOnly: true, kind: 'quiet', size: 's', disabled: i === docs.length - 1, onClick: function () { moveDoc(P, i, 1); } });
      var rm = btn('Remove', { icon: 'trash', iconOnly: true, kind: 'quiet', size: 's', cls: 'es-danger-q', title: 'Remove document', onClick: function (e, b) { removeDoc(P, d, b); } });
      ul.appendChild(h('li', { class: 'es-doc', data: { id: d.id } }, thumb,
        h('div', { class: 'es-doc-i' }, h('div', { class: 'es-doc-n', text: d.name || 'Document' }),
          h('div', { class: 'es-doc-m', text: plural(docPages(d).length, 'page') + (d.size ? ' · ' + fmtSize(d.size) : '') +
            (sourceLabel(d) ? ' · converted from ' + sourceLabel(d) : '') })),
        h('div', { class: 'es-doc-a' }, up, dn, rm)));
    });
    el.appendChild(ul);
  }

  function pageImg(src, alt, eager) {
    var img = h('img', { src: src, alt: alt, loading: eager ? null : 'lazy', decoding: 'async', draggable: 'false' });
    var tries = 0;
    img.addEventListener('error', function () {
      tries++;
      if (tries <= 2) {
        setTimeout(function () { img.src = src + (src.indexOf('?') >= 0 ? '&' : '?') + 'r=' + tries; }, 1200 * tries);
      } else if (img.parentNode) img.parentNode.classList.add('es-img-err');
    });
    return img;
  }

  function moveDoc(P, i, dir) {
    var docs = P.env.documents, j = i + dir;
    if (j < 0 || j >= docs.length) return;
    var prev = docs.slice();
    var t = docs[i]; docs[i] = docs[j]; docs[j] = t;
    docs.forEach(function (d, k) { d.order = k; });
    renderDocList(P);
    var focusSel = '.es-doc[data-id="' + (window.CSS && CSS.escape ? CSS.escape(t.id) : t.id) + '"] button[aria-label="' + (dir < 0 ? 'Move up' : 'Move down') + '"]';
    var fb = P.ui.docsEl && P.ui.docsEl.querySelector(focusSel);
    if (fb && !fb.disabled) fb.focus(); else if (fb) { var o = fb.parentNode.querySelector('button:not([disabled])'); if (o) o.focus(); }
    var order = docs.map(function (d) { return d.id; });
    P.uploading++; saveIndicator(P);
    enqueue(P, function () {
      return EP.orderDocs(P.eid, order).then(function (env) {
        P.uploading--;
        if (env && Array.isArray(env.documents) && env.documents.length === P.env.documents.length) {
          var byId = {};
          env.documents.forEach(function (d) { byId[d.id] = d; });
          if (P.env.documents.every(function (d) { return byId[d.id]; })) P.env.documents = normDocs(env.documents);
        }
        saveIndicator(P);
      }, function (err) {
        P.uploading--;
        P.env.documents = prev;
        saveIndicator(P);
        renderDocList(P);
        toast('Couldn’t reorder: ' + errMsg(err), 'err');
      });
    });
  }

  function removeDoc(P, d, b) {
    var nf = P.fields.filter(function (f) { return f.document_id === d.id; }).length;
    confirmDialog('Remove “' + (d.name || 'this document') + '” from the envelope?' + (nf ? '\n\n' + plural(nf, 'field') + ' placed on it will also be removed.' : ''),
      { title: 'Remove document', okLabel: 'Remove', danger: true }).then(function (ok) {
      if (!ok) return;
      setBusy(b, true);
      P.uploading++; saveIndicator(P);
      enqueue(P, function () {
        return EP.removeDoc(P.eid, d.id).then(function () {
          P.uploading--;
          P.env.documents = P.env.documents.filter(function (x) { return x.id !== d.id; });
          P.env.documents.forEach(function (x, k) { x.order = k; });
          P.fields = P.fields.filter(function (f) { return f.document_id !== d.id; });
          if (P.sel && !P.fields.some(function (f) { return f.id === P.sel; })) P.sel = null;
          saveIndicator(P);
          renderDocList(P);
          renderSteps(P);
          toast('Document removed.', 'ok');
        }, function (err) {
          P.uploading--; saveIndicator(P); setBusy(b, false);
          toast('Couldn’t remove: ' + errMsg(err), 'err');
        });
      });
    });
  }

  /* ---- Step 2: recipients */
  function renderRecipStep(P, body) {
    var pane = h('div', { class: 'es-pane es-mid' });
    pane.appendChild(h('div', { class: 'es-pane-head' }, h('h3', { class: 'es-h3', text: 'Add recipients' }),
      h('p', { class: 'es-sub', text: P.env.email_available
        ? 'Each recipient gets their own private link, and ' + B() + ' emails it to them when you send (you can turn that off on the last step).'
        : 'Each recipient gets their own private link. ' + B() + ' doesn’t email the links — after sending, you’ll copy each link (or open it in your mail app) and share it yourself.' })));
    var labelId = uid('seq');
    var sw = h('button', { type: 'button', class: 'es-switch', role: 'switch', 'aria-checked': P.sequential ? 'true' : 'false', 'aria-labelledby': labelId },
      h('span', { class: 'es-switch-k', 'aria-hidden': 'true' }));
    P.ui.seqHint = h('div', { class: 'es-hint' });
    sw.addEventListener('click', function () { toggleSequential(P, !P.sequential); sw.setAttribute('aria-checked', P.sequential ? 'true' : 'false'); });
    pane.appendChild(h('div', { class: 'es-seq' }, sw, h('div', null, h('div', { class: 'es-seq-t', id: labelId, text: 'Set signing order' }), P.ui.seqHint)));
    P.ui.rlist = h('div', { class: 'es-rlist', role: 'list' });
    pane.appendChild(P.ui.rlist);
    pane.appendChild(h('div', { class: 'es-radd' }, btn('Add recipient', { icon: 'plus', onClick: function () { addRecip(P, true); } })));
    body.appendChild(pane);
    P.stepOff.push(function () { P.ui.rlist = null; P.ui.seqHint = null; P.recips.forEach(function (r) { r._ui = null; }); });
    if (!P.recips.length) addRecip(P, false);
    else renderRecipRows(P);
  }

  function updateSeqHint(P) {
    if (!P.ui.seqHint) return;
    P.ui.seqHint.textContent = P.sequential
      ? 'On — recipients act in order (1, then 2, …). Give people the same number to let them act at the same time.'
      : 'Off — everyone can act at the same time.';
  }
  function nextColor(P) {
    var used = {};
    P.recips.forEach(function (r) { if (r.color != null) used[r.color] = 1; });
    for (var i = 0; i < 8; i++) if (!used[i]) return i;
    return P.recips.length % 8;
  }
  function addRecip(P, focus) {
    var maxOrder = P.recips.reduce(function (a, r) { return Math.max(a, r.routing_order || 1); }, 0);
    var r = { _k: uid('rk'), id: null, name: '', email: '', role: 'signer', routing_order: P.sequential ? Math.min(99, maxOrder + 1) : 1,
      note: '', color: nextColor(P), access_code_set: false, email_code: false, ecSaved: false,
      codeAction: null, code: '', open: false, touched: {}, status: 'created' };
    P.recips.push(r);
    renderRecipRows(P);
    if (focus && r._ui) r._ui.nameIn.focus();
  }
  function renumber(P) { P.recips.forEach(function (r, i) { r.routing_order = Math.min(99, i + 1); }); }
  function toggleSequential(P, on) {
    P.sequential = on;
    if (on) renumber(P); else P.recips.forEach(function (r) { r.routing_order = 1; });
    renderRecipRows(P);
    P.savers.recips.schedule(300);
    P.savers.meta.schedule(300);
  }
  function sortByOrder(P) {
    var idx = new Map();
    P.recips.forEach(function (r, i) { idx.set(r, i); });
    P.recips.sort(function (a, b) { return (a.routing_order - b.routing_order) || (idx.get(a) - idx.get(b)); });
  }

  function renderRecipRows(P) {
    var list = P.ui.rlist;
    if (!list) return;
    updateSeqHint(P);
    list.textContent = '';
    list.classList.toggle('es-seq-on', P.sequential);
    P.recips.forEach(function (r, i) { list.appendChild(recipRow(P, r, i)); });
    renderSteps(P);
  }

  function recipColor(r) { return colorOf(r.color); }

  function recipRow(P, r, i) {
    var n = P.recips.length;
    var ui = r._ui = {};
    var row = h('div', { class: 'es-rrow', role: 'listitem', data: { k: r._k }, style: { '--es-c': recipColor(r) } });
    var title = rName(r) === 'Recipient' ? 'recipient ' + (i + 1) : rName(r);

    if (P.sequential) {
      ui.ordIn = h('input', { class: 'es-in es-in-ord', type: 'number', min: '1', max: '99', inputmode: 'numeric', value: String(r.routing_order), 'aria-label': 'Signing order for ' + title });
      ui.ordIn.addEventListener('change', function () {
        r.routing_order = clampInt(ui.ordIn.value, 1, 99, r.routing_order);
        sortByOrder(P);
        renderRecipRows(P);
        if (r._ui && r._ui.ordIn) r._ui.ordIn.focus();
        P.savers.recips.schedule();
      });
      var up = btn('Move ' + title + ' up', { icon: 'up', iconOnly: true, kind: 'quiet', size: 's', disabled: i === 0, onClick: function () { moveRecip(P, r, -1, 'up'); } });
      var dn = btn('Move ' + title + ' down', { icon: 'down', iconOnly: true, kind: 'quiet', size: 's', disabled: i === n - 1, onClick: function () { moveRecip(P, r, 1, 'down'); } });
      up.dataset.mv = 'up'; dn.dataset.mv = 'down';
      row.appendChild(h('div', { class: 'es-r-ord' }, ui.ordIn, h('div', { class: 'es-r-mv' }, up, dn)));
    }
    ui.dot = h('span', { class: 'es-r-dot', 'aria-hidden': 'true' });
    row.appendChild(ui.dot);

    ui.nameIn = h('input', { class: 'es-in', type: 'text', maxlength: '120', autocomplete: 'off', placeholder: 'Full name', value: r.name });
    ui.nameErr = h('div', { class: 'es-err', id: uid('err') });
    ui.nameIn.setAttribute('aria-describedby', ui.nameErr.id);
    ui.emailIn = h('input', { class: 'es-in', type: 'email', maxlength: '200', autocomplete: 'off', placeholder: 'name@company.com', value: r.email });
    ui.emailErr = h('div', { class: 'es-err', id: uid('err') });
    ui.emailIn.setAttribute('aria-describedby', ui.emailErr.id);
    ui.roleSel = h('select', { class: 'es-in es-sel', value: r.role },
      ROLES.map(function (k) { return h('option', { value: k, text: ROLE_LABEL[k] }); }));

    ui.nameIn.addEventListener('input', function () { r.name = ui.nameIn.value; if (r.touched.name) showRowErrors(r); });
    ui.nameIn.addEventListener('change', function () { r.name = ui.nameIn.value; P.savers.recips.schedule(); });
    ui.nameIn.addEventListener('blur', function () { if (!isBlankNew(r)) { r.touched.name = true; showRowErrors(r); } });
    ui.emailIn.addEventListener('input', function () { r.email = ui.emailIn.value; if (r.touched.email) showRowErrors(r); });
    ui.emailIn.addEventListener('change', function () { r.email = ui.emailIn.value.trim(); ui.emailIn.value = r.email; P.savers.recips.schedule(); });
    ui.emailIn.addEventListener('blur', function () { if (!isBlankNew(r)) { r.touched.email = true; showRowErrors(r); } });
    ui.roleSel.addEventListener('change', function () { changeRole(P, r, ui.roleSel.value); });

    var nf = h('div', { class: 'es-r-f es-r-name' }, h('label', { class: 'es-lbl', for: (ui.nameIn.id = uid('rn')), text: 'Name' }), ui.nameIn, ui.nameErr);
    var ef = h('div', { class: 'es-r-f es-r-email' }, h('label', { class: 'es-lbl', for: (ui.emailIn.id = uid('re')), text: 'Email' }), ui.emailIn, ui.emailErr);
    var rf = h('div', { class: 'es-r-f es-r-role' }, h('label', { class: 'es-lbl', for: (ui.roleSel.id = uid('rr')), text: 'Role' }), ui.roleSel);
    row.appendChild(h('div', { class: 'es-r-fields' }, nf, ef, rf));

    var moreId = uid('more');
    ui.moreBtn = h('button', { type: 'button', class: 'es-btn es-btn-quiet es-btn-s es-r-morebtn', 'aria-expanded': r.open ? 'true' : 'false', 'aria-controls': moreId },
      icon('sliders'), h('span', { class: 'es-btn-t', text: 'Options' }), ui.badge = h('span', { class: 'es-r-badge' }));
    var rm = btn('Remove ' + title, { icon: 'trash', iconOnly: true, kind: 'quiet', size: 's', cls: 'es-danger-q', onClick: function () { removeRecip(P, r); } });
    row.appendChild(h('div', { class: 'es-r-acts' }, ui.moreBtn, rm));

    // options panel: access code + email one-time code + private note
    ui.more = h('div', { class: 'es-r-more', id: moreId, hidden: !r.open });
    ui.codeIn = h('input', { class: 'es-in', type: 'password', maxlength: '64', autocomplete: 'new-password', value: r.codeAction === 'set' ? r.code : '' });
    ui.codeShow = btn('Show code', { icon: 'eye', iconOnly: true, kind: 'quiet', size: 's', aria: { 'aria-pressed': 'false' }, onClick: function () {
      var show = ui.codeIn.type === 'password';
      ui.codeIn.type = show ? 'text' : 'password';
      ui.codeShow.setAttribute('aria-pressed', show ? 'true' : 'false');
      ui.codeShow.replaceChild(icon(show ? 'eyeoff' : 'eye'), ui.codeShow.firstChild);
    } });
    ui.codeIn.addEventListener('change', function () {
      var v = ui.codeIn.value;
      if (v) { r.codeAction = 'set'; r.code = v; } else if (r.codeAction === 'set') { r.codeAction = null; r.code = ''; }
      refreshCodeUi(P, r);
      P.savers.recips.schedule();
    });
    ui.codeState = h('div', { class: 'es-code-state' });
    var codeId = (ui.codeIn.id = uid('rc'));
    ui.ecIn = h('input', { type: 'checkbox', id: uid('rec'), class: 'es-cbx', checked: r.email_code });
    ui.ecHint = h('div', { class: 'es-hint', id: uid('rech') });
    ui.ecIn.setAttribute('aria-describedby', ui.ecHint.id);
    ui.ecIn.addEventListener('change', function () { r.email_code = ui.ecIn.checked; refreshCodeUi(P, r); P.savers.recips.schedule(); });
    ui.noteIn = h('textarea', { class: 'es-in es-ta', rows: '3', maxlength: '1000', placeholder: 'Only this recipient will see this note.', value: r.note });
    ui.noteIn.addEventListener('change', function () { r.note = ui.noteIn.value; refreshCodeUi(P, r); P.savers.recips.schedule(); });
    var noteId = (ui.noteIn.id = uid('rnote'));
    ui.more.appendChild(h('div', { class: 'es-r-mgrid' },
      h('div', { class: 'es-r-f' }, h('label', { class: 'es-lbl', for: codeId, text: 'Access code (optional)' }),
        h('div', { class: 'es-pw' }, ui.codeIn, ui.codeShow), ui.codeState,
        h('div', { class: 'es-r-ec' }, h('label', { class: 'es-check', for: ui.ecIn.id }, ui.ecIn, h('span', { text: 'Email them a one-time code' })), ui.ecHint)),
      h('div', { class: 'es-r-f' }, h('label', { class: 'es-lbl', for: noteId, text: 'Private note' }), ui.noteIn)));
    ui.moreBtn.addEventListener('click', function () {
      r.open = !r.open;
      ui.more.hidden = !r.open;
      ui.moreBtn.setAttribute('aria-expanded', r.open ? 'true' : 'false');
      if (r.open) ui.codeIn.focus();
    });
    row.appendChild(ui.more);
    ui.row = row;
    refreshCodeUi(P, r);
    showRowErrors(r);
    return row;
  }

  function refreshCodeUi(P, r) {
    var ui = r._ui;
    if (!ui) return;
    ui.dot.style.background = recipColor(r);
    ui.row.style.setProperty('--es-c', recipColor(r));
    var st = ui.codeState;
    st.textContent = '';
    if (r.codeAction === 'clear') {
      st.appendChild(h('span', { class: 'es-hint es-warn-t', text: 'The access code will be removed. ' }));
      st.appendChild(h('button', { type: 'button', class: 'es-linkbtn', text: 'Undo', on: { click: function () { r.codeAction = null; refreshCodeUi(P, r); P.savers.recips.schedule(); } } }));
      ui.codeIn.placeholder = '';
      ui.codeIn.disabled = true;
    } else {
      ui.codeIn.disabled = false;
      if (r.access_code_set) {
        ui.codeIn.placeholder = '•••••• (set) — leave blank to keep';
        st.appendChild(h('span', { class: 'es-hint', text: r.codeAction === 'set' ? 'A new code will replace the current one. ' : 'A code is set. Type a new one to change it. ' }));
        st.appendChild(h('button', { type: 'button', class: 'es-linkbtn es-danger-t', text: 'Remove code', on: { click: function () {
          r.codeAction = 'clear'; r.code = ''; ui.codeIn.value = ''; refreshCodeUi(P, r); P.savers.recips.schedule();
        } } }));
      } else {
        ui.codeIn.placeholder = 'No code';
        st.appendChild(h('span', { class: 'es-hint', text: 'They must enter it before they can open anything. Share it separately, e.g. by phone.' }));
      }
    }
    var ec = emailCodeState(r.email_code);
    ui.ecIn.checked = r.email_code;
    ui.ecIn.disabled = ec.disabled;
    ui.ecHint.className = 'es-hint' + (ec.warn ? ' es-warn-t' : '');
    ui.ecHint.textContent = ec.hint;
    var hasCode = (r.access_code_set && r.codeAction !== 'clear') || r.codeAction === 'set';
    var hasNote = !!r.note.trim();
    // 'code' = a code is needed to open the link (access code and/or email code); the badge must fit the fixed
    // actions column
    ui.badge.textContent = [hasCode || r.email_code ? 'code' : '', hasNote ? 'note' : '']
      .filter(Boolean).join(' · ');
  }
  function ecHintText() { return 'Before they can open anything, ' + B() + ' emails a 6-digit code to their address for them to enter.'; }
  /** The 'Email them a one-time code' checkbox for a recipient who has it on / off: {disabled, hint, warn}.
   *  Switching it on needs an outgoing mail server; switching it off never does. */
  function emailCodeState(on) {
    if (!S.cfg) return { disabled: !on, hint: on ? ecHintText() : '' };          // capabilities still loading
    if (S.cfg.email_codes) return { disabled: false, hint: ecHintText() };
    if (on) return { disabled: false, warn: true, hint: 'No outgoing mail server is set up on this server, so the code can’t be sent. Untick this, or use an access code instead.' };
    return { disabled: true, hint: 'Needs an outgoing mail server — not set up on this server.' };
  }
  function refreshRecipMeta(P) {
    P.recips.forEach(function (r) { if (r._ui) refreshCodeUi(P, r); });
    renderSteps(P);
    if (P.step === 3 && P.ed) renderSignerPicker(P);
  }
  function showRowErrors(r) {
    var ui = r._ui;
    if (!ui) return;
    var e = isBlankNew(r) ? {} : rowErrors(r);
    var ne = r.touched.name ? e.name : null, ee = r.touched.email ? e.email : null;
    ui.nameErr.textContent = ne || '';
    ui.emailErr.textContent = ee || '';
    if (ne) ui.nameIn.setAttribute('aria-invalid', 'true'); else ui.nameIn.removeAttribute('aria-invalid');
    if (ee) ui.emailIn.setAttribute('aria-invalid', 'true'); else ui.emailIn.removeAttribute('aria-invalid');
  }
  function refreshRecipErrors(P) { P.recips.forEach(showRowErrors); }

  function changeRole(P, r, role) {
    var prev = r.role;
    var nf = r.id ? P.fields.filter(function (f) { return f.recipient_id === r.id; }).length : 0;
    function apply() {
      r.role = role;
      refreshCodeUi(P, r);
      if (prev === 'signer' && role !== 'signer' && nf) {
        P.fields = P.fields.filter(function (f) { return f.recipient_id !== r.id; });
        P.fieldsVer++;
        P.savers.fields.schedule(0);         // runs before the recipients save (serial queue)
      }
      P.savers.recips.schedule();
      renderSteps(P);
    }
    if (prev === 'signer' && role !== 'signer' && nf) {
      confirmDialog(rName(r) + ' has ' + plural(nf, 'field') + ' placed. Only people who need to sign can have fields, so these will be removed.',
        { title: 'Change role', okLabel: 'Change role & remove fields', danger: true }).then(function (ok) {
        if (ok) apply(); else if (r._ui) r._ui.roleSel.value = prev;
      });
    } else apply();
  }

  function moveRecip(P, r, dir, which) {
    var i = P.recips.indexOf(r), j = i + dir;
    if (i < 0 || j < 0 || j >= P.recips.length) return;
    var o = P.recips[j];
    P.recips[j] = r; P.recips[i] = o;
    var t = r.routing_order; r.routing_order = o.routing_order; o.routing_order = t;
    renderRecipRows(P);
    if (r._ui) {
      var b = r._ui.row.querySelector('[data-mv="' + which + '"]');
      if (b && b.disabled) b = r._ui.row.querySelector('.es-r-mv button:not([disabled])');
      if (b) b.focus();
    }
    P.savers.recips.schedule();
  }

  function removeRecip(P, r) {
    var nf = r.id ? P.fields.filter(function (f) { return f.recipient_id === r.id; }).length : 0;
    function go() {
      var i = P.recips.indexOf(r);
      if (i < 0) return;
      P.recips.splice(i, 1);
      if (r.id && nf) {
        P.fields = P.fields.filter(function (f) { return f.recipient_id !== r.id; });
        P.fieldsVer++;
      }
      if (P.sequential) {
        var distinct = [];
        P.recips.forEach(function (x) { if (distinct.indexOf(x.routing_order) < 0) distinct.push(x.routing_order); });
        distinct.sort(function (a, b) { return a - b; });
        P.recips.forEach(function (x) { x.routing_order = distinct.indexOf(x.routing_order) + 1; });
      }
      renderRecipRows(P);
      var next = P.recips[Math.min(i, P.recips.length - 1)];
      if (next && next._ui) next._ui.nameIn.focus();
      if (r.id) P.savers.recips.schedule(300);
      else if (P.savers.recips.blocked) P.savers.recips.schedule(300);
    }
    if (nf) {
      confirmDialog('Remove ' + rName(r) + '? Their ' + plural(nf, 'field') + ' will also be removed.', { title: 'Remove recipient', okLabel: 'Remove', danger: true })
        .then(function (ok) { if (ok) go(); });
    } else go();
  }

  /* ---- Step 3: field editor */
  function serverRole(P, id) {
    var s = arr(P.env.recipients).filter(function (x) { return x.id === id; })[0];
    return s ? s.role : null;
  }
  /** Recipients who can own fields: saved, and a signer both locally and on the server. */
  function signersOf(P) { return P.recips.filter(function (r) { return r.role === 'signer' && r.id && serverRole(P, r.id) === 'signer'; }); }
  function recipById(P, id) { return P.recips.filter(function (r) { return r.id === id; })[0] || null; }
  function findField(P, id) { return P.fields.filter(function (f) { return f.id === id; })[0] || null; }
  function fieldColor(P, f) { var r = recipById(P, f.recipient_id); return r ? recipColor(r) : '#8d897f'; }

  function renderFieldsStep(P, body) {
    var docs = P.env.documents;
    var signers = signersOf(P);
    if (!signers.some(function (s) { return s.id === P.activeSigner; })) P.activeSigner = signers.length ? signers[0].id : null;
    if (P.sel && !findField(P, P.sel)) P.sel = null;
    var ed = P.ed = { pages: [], byKey: {}, fieldEls: {}, cur: null, suppressClick: false };

    var root = h('div', { class: 'es-ed' + (P.sel ? ' es-has-sel' : '') });
    ed.root = root;

    // ----- left rail
    var left = h('aside', { class: 'es-ed-left', 'aria-label': 'Recipients and field types' });
    ed.picker = h('div', { class: 'es-ed-rcps', role: 'radiogroup', 'aria-label': 'Place fields for' });
    left.appendChild(h('div', { class: 'es-ed-sec' }, h('div', { class: 'es-lbl', text: 'Placing fields for' }), ed.picker));
    ed.palette = h('div', { class: 'es-ed-pal', role: 'group', 'aria-label': 'Field types' });
    FIELD_TYPES.forEach(function (ft) { ed.palette.appendChild(paletteItem(P, ft)); });
    left.appendChild(h('div', { class: 'es-ed-sec' }, h('div', { class: 'es-lbl', text: 'Fields' }),
      h('div', { class: 'es-hint es-ed-palhint', text: 'Drag onto a page, or click to add to the page in view.' }), ed.palette));
    ed.thumbs = h('div', { class: 'es-ed-thumbs' });
    left.appendChild(h('div', { class: 'es-ed-sec es-ed-sec-th' }, h('div', { class: 'es-lbl', text: 'Pages' }), ed.thumbs));
    root.appendChild(left);

    // ----- centre
    var main = h('div', { class: 'es-ed-main' });
    ed.jump = h('select', { class: 'es-in es-sel es-ed-jump', 'aria-label': 'Jump to page' });
    var zoomGrp = h('div', { class: 'es-seg', role: 'group', 'aria-label': 'Zoom' });
    [['fit', 'Fit width'], ['100', '100%'], ['150', '150%']].forEach(function (z) {
      zoomGrp.appendChild(h('button', { type: 'button', class: 'es-seg-b', 'aria-pressed': P.zoom === z[0] ? 'true' : 'false', data: { z: z[0] }, text: z[1],
        on: { click: function () { setZoom(P, z[0]); } } }));
    });
    ed.zoomGrp = zoomGrp;
    ed.countEl = h('span', { class: 'es-ed-count', 'aria-live': 'polite' });
    main.appendChild(h('div', { class: 'es-ed-bar' }, ed.jump, zoomGrp, h('div', { class: 'es-grow' }), ed.countEl));
    ed.scroll = h('div', { class: 'es-ed-scroll', tabindex: '-1' });
    ed.pagesEl = h('div', { class: 'es-ed-pages es-z-' + P.zoom });
    ed.scroll.appendChild(ed.pagesEl);
    main.appendChild(ed.scroll);
    root.appendChild(main);

    // ----- right
    ed.right = h('aside', { class: 'es-ed-right', 'aria-label': 'Field properties' });
    root.appendChild(ed.right);
    body.appendChild(root);

    if (P.savers.recips.blocked || P.recips.some(function (r) { return r.role === 'signer' && !r.id && !isBlankNew(r); })) {
      ed.pagesEl.appendChild(callout('amber', 'alert', 'Some recipients aren’t saved yet', 'Fix their details in Recipients to place fields for them.',
        h('button', { type: 'button', class: 'es-linkbtn', text: 'Go to Recipients', on: { click: function () { goStep(P, 2); } } })));
    }

    if (!docs.length) {
      ed.pagesEl.appendChild(emptyState('doc', 'No documents yet', 'Add a document before placing fields.',
        btn('Add documents', { kind: 'primary', onClick: function () { goStep(P, 1); } })));
    }
    var jumpGroupsDone = 0;
    docs.forEach(function (d, di) {
      var pages = docPages(d);
      var grp = h('section', { class: 'es-ed-doc', 'aria-label': d.name || 'Document ' + (di + 1) });
      grp.appendChild(h('div', { class: 'es-ed-doch' }, icon('doc'), h('span', { text: d.name || 'Document ' + (di + 1) }),
        h('span', { class: 'es-dimtxt', text: ' · ' + plural(pages.length, 'page') })));
      var og = h('optgroup', { label: (d.name || 'Document ' + (di + 1)).slice(0, 60) });
      var thGrp = h('div', { class: 'es-th-grp' }, docs.length > 1 ? h('div', { class: 'es-th-doc', text: d.name || 'Document ' + (di + 1) }) : null);
      var thGrid = h('div', { class: 'es-th-grid' });
      pages.forEach(function (pg, pi) {
        var n = pi + 1, key = d.id + ':' + n;
        var entry = makePage(P, d, n, pages.length, pg);
        grp.appendChild(entry.wrap);
        og.appendChild(h('option', { value: key, text: 'Page ' + n + ' of ' + pages.length }));
        var tb = h('button', { type: 'button', class: 'es-th', 'aria-label': (d.name || 'Document') + ', page ' + n, data: { key: key },
          on: { click: function () { scrollToPage(P, key); } } },
        h('span', { class: 'es-th-img', style: { aspectRatio: pg.w + ' / ' + pg.h } }, pageImg(EP.pageUrl(P.eid, d.id, n, VIEW_SCALE), '')),
        h('span', { class: 'es-th-n', text: String(n) }));
        entry.thumb = tb;
        thGrid.appendChild(tb);
      });
      thGrp.appendChild(thGrid);
      ed.thumbs.appendChild(thGrp);
      ed.jump.appendChild(og);
      ed.pagesEl.appendChild(grp);
      jumpGroupsDone++;
    });
    if (!jumpGroupsDone) ed.jump.appendChild(h('option', { value: '', text: 'No pages' }));
    ed.jump.addEventListener('change', function () { if (ed.jump.value) scrollToPage(P, ed.jump.value); });

    applyZoom(P);
    P.fields.forEach(function (f) { mountField(P, f); });
    renderSignerPicker(P);
    renderProps(P);
    updateCount(P);

    var raf = 0;
    function onScroll() {
      if (raf) return;
      raf = requestAnimationFrame(function () { raf = 0; updateCurrentPage(P); });
    }
    ed.scroll.addEventListener('scroll', onScroll, { passive: true });
    P.stepOff.push(function () { if (raf) cancelAnimationFrame(raf); ed.scroll.removeEventListener('scroll', onScroll); });
    setTimeout(function () { if (P.ed === ed) updateCurrentPage(P); }, 60);
    if (P.sel) setTimeout(function () { var el = ed.fieldEls[P.sel]; if (el && P.ed === ed) { try { el.scrollIntoView({ block: 'center' }); } catch (e) { /* ignore */ } revealSel(P); } }, 80);
  }

  function makePage(P, d, n, total, pg) {
    var ed = P.ed;
    var key = d.id + ':' + n;
    var page = h('div', { class: 'es-pg', data: { key: key }, style: { aspectRatio: pg.w + ' / ' + pg.h } });
    var img = pageImg(EP.pageUrl(P.eid, d.id, n, VIEW_SCALE), (d.name || 'Document') + ', page ' + n + ' of ' + total);
    var layer = h('div', { class: 'es-pg-layer' });
    page.appendChild(img);
    page.appendChild(layer);
    page.addEventListener('pointerdown', function (e) {
      if (e.target === page || e.target === layer || e.target === img) { if (P.sel) select(P, null); }
    });
    var wrap = h('div', { class: 'es-pg-wrap', data: { key: key } },
      h('div', { class: 'es-pg-lbl' }, h('span', { text: 'Page ' + n + ' of ' + total })), page);
    var entry = { key: key, wrap: wrap, el: page, layer: layer, doc: d, n: n, size: pg, thumb: null };
    ed.pages.push(entry);
    ed.byKey[key] = entry;
    return entry;
  }

  function applyZoom(P) {
    var ed = P.ed;
    if (!ed) return;
    ed.pagesEl.className = 'es-ed-pages es-z-' + P.zoom;
    ed.pages.forEach(function (pe) {
      if (P.zoom === 'fit') pe.wrap.style.width = '';
      else pe.wrap.style.width = Math.round(pe.size.w * (96 / 72) * (P.zoom === '150' ? 1.5 : 1)) + 'px';
    });
    Array.prototype.forEach.call(ed.zoomGrp.querySelectorAll('.es-seg-b'), function (b) {
      b.setAttribute('aria-pressed', b.dataset.z === P.zoom ? 'true' : 'false');
    });
  }
  function setZoom(P, z) {
    if (!P.ed) return;
    var cur = P.ed.cur;
    P.zoom = z;
    applyZoom(P);
    if (cur) scrollToPage(P, cur.key, true);
  }
  function scrollToPage(P, key, instant) {
    var ed = P.ed;
    var pe = ed && ed.byKey[key];
    if (!pe) return;
    var sr = ed.scroll.getBoundingClientRect(), pr = pe.wrap.getBoundingClientRect();
    var top = ed.scroll.scrollTop + (pr.top - sr.top) - 12;
    try { ed.scroll.scrollTo({ top: top, behavior: instant ? 'auto' : 'smooth' }); } catch (e) { ed.scroll.scrollTop = top; }
    setCurrentPage(P, pe);
  }
  function updateCurrentPage(P) {
    var ed = P.ed;
    if (!ed || !ed.pages.length) return;
    var sr = ed.scroll.getBoundingClientRect(), best = null, bestA = -1;
    for (var i = 0; i < ed.pages.length; i++) {
      var r = ed.pages[i].el.getBoundingClientRect();
      if (r.bottom < sr.top - 2000) continue;
      if (r.top > sr.bottom) break;
      var vis = Math.max(0, Math.min(r.bottom, sr.bottom) - Math.max(r.top, sr.top));
      if (vis > bestA) { bestA = vis; best = ed.pages[i]; }
    }
    if (best) setCurrentPage(P, best);
  }
  function setCurrentPage(P, pe) {
    var ed = P.ed;
    if (!ed || ed.cur === pe) return;
    if (ed.cur && ed.cur.thumb) { ed.cur.thumb.classList.remove('es-cur'); ed.cur.thumb.removeAttribute('aria-current'); }
    ed.cur = pe;
    if (pe.thumb) {
      pe.thumb.classList.add('es-cur');
      pe.thumb.setAttribute('aria-current', 'page');
      var tr = pe.thumb.getBoundingClientRect(), cr = ed.thumbs.closest('.es-ed-left').getBoundingClientRect();
      if (tr.top < cr.top || tr.bottom > cr.bottom) { try { pe.thumb.scrollIntoView({ block: 'nearest' }); } catch (e) { /* ignore */ } }
    }
    if (ed.jump.value !== pe.key) ed.jump.value = pe.key;
  }

  function renderSignerPicker(P) {
    var ed = P.ed;
    if (!ed) return;
    var signers = signersOf(P);
    if (!signers.some(function (s) { return s.id === P.activeSigner; })) P.activeSigner = signers.length ? signers[0].id : null;
    ed.picker.textContent = '';
    if (!signers.length) {
      ed.picker.appendChild(h('div', { class: 'es-ed-nosig' }, h('p', { class: 'es-hint', text: 'Add at least one recipient who needs to sign — fields belong to signers.' }),
        btn('Add a signer', { size: 's', icon: 'plus', onClick: function () { goStep(P, 2); } })));
    }
    signers.forEach(function (s) {
      var on = s.id === P.activeSigner;
      var count = P.fields.filter(function (f) { return f.recipient_id === s.id; }).length;
      var b = h('button', { type: 'button', class: 'es-ed-rcp' + (on ? ' es-on' : ''), role: 'radio', 'aria-checked': on ? 'true' : 'false',
        tabindex: on ? '0' : '-1', style: { '--es-c': recipColor(s) } },
      h('span', { class: 'es-r-dot', 'aria-hidden': 'true' }),
      h('span', { class: 'es-ed-rcp-n' }, h('span', { class: 'es-ed-rcp-nm', text: rName(s) }), h('span', { class: 'es-ed-rcp-c', text: plural(count, 'field') })));
      b.addEventListener('click', function () { P.activeSigner = s.id; renderSignerPicker(P); var nb = ed.picker.querySelector('.es-on'); if (nb) nb.focus(); });
      ed.picker.appendChild(b);
    });
    ed.picker.onkeydown = function (e) {
      if (['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].indexOf(e.key) < 0 || signers.length < 2) return;
      e.preventDefault();
      var i = signers.map(function (s) { return s.id; }).indexOf(P.activeSigner);
      i = (i + ((e.key === 'ArrowDown' || e.key === 'ArrowRight') ? 1 : -1) + signers.length) % signers.length;
      P.activeSigner = signers[i].id;
      renderSignerPicker(P);
      var nb = ed.picker.querySelector('.es-on'); if (nb) nb.focus();
    };
    // no signer yet: P.activeSigner is null, which must not match an unsaved recipient row (id null) — the palette shows as disabled
    var active = P.activeSigner ? recipById(P, P.activeSigner) : null;
    ed.palette.style.setProperty('--es-c', active ? recipColor(active) : '#8d897f');
    Array.prototype.forEach.call(ed.palette.querySelectorAll('.es-pal'), function (b) { b.disabled = !active; });
  }

  function paletteItem(P, ft) {
    var b = h('button', { type: 'button', class: 'es-pal', title: ft.label + ' (' + ft.w + '×' + ft.h + ' pt)' }, icon(ft.icon), h('span', { text: ft.label }));
    b.addEventListener('click', function () {
      if (P.ed && P.ed.suppressClick) { P.ed.suppressClick = false; return; }
      addFieldInView(P, ft.type);
    });
    b.addEventListener('pointerdown', function (e) { paletteDrag(P, e, ft, b); });
    return b;
  }

  function pageAt(P, x, y) {
    var el = document.elementFromPoint(x, y);
    var pg = el && el.closest ? el.closest('.es-pg') : null;
    if (!pg || !P.ed || !P.ed.root.contains(pg)) return null;
    return P.ed.byKey[pg.dataset.key] || null;
  }

  function paletteDrag(P, e, ft, b) {
    if (e.button !== 0 || !P.activeSigner || !P.ed || b.disabled) return;
    var ed = P.ed, sx = e.clientX, sy = e.clientY, ghost = null, over = null, pid = e.pointerId;
    try { b.setPointerCapture(pid); } catch (err) { /* ignore */ }
    function ppt(pe) { var r = pe.el.getBoundingClientRect(); return r.width / pe.size.w; }
    function move(ev) {
      if (ev.pointerId !== pid) return;
      if (!ghost) {
        if (Math.abs(ev.clientX - sx) + Math.abs(ev.clientY - sy) < 6) return;
        // the ghost carries the field-type class and the default 'required' star, so it previews the placed field
        ghost = h('div', { class: 'es-ghost es-fld-' + ft.type, style: { '--es-c': fieldColor(P, { recipient_id: P.activeSigner }) } },
          h('span', { class: 'es-fld-t', text: (ft.short || '') + (ft.type !== 'checkbox' ? ' *' : '') }));
        if (ft.type === 'checkbox') ghost.appendChild(icon('check'));
        S.root.appendChild(ghost);
        ed.suppressClick = true;
        S.root.classList.add('es-dragging');
      }
      var target = pageAt(P, ev.clientX, ev.clientY);
      if (target !== over) {
        if (over) over.el.classList.remove('es-drop-ok');
        over = target;
        if (over) over.el.classList.add('es-drop-ok');
      }
      var ref = over || ed.cur || ed.pages[0];
      var k = ref ? ppt(ref) : 1;
      var rr = S.root.getBoundingClientRect();
      ghost.style.left = (ev.clientX - rr.left) + 'px';
      ghost.style.top = (ev.clientY - rr.top) + 'px';
      ghost.style.width = Math.max(12, ft.w * k) + 'px';
      ghost.style.height = Math.max(12, ft.h * k) + 'px';
      ghost.classList.toggle('es-ghost-no', !over);
    }
    function end(ev, cancelled) {
      if (ev.pointerId !== pid) return;
      b.removeEventListener('pointermove', move);
      b.removeEventListener('pointerup', up);
      b.removeEventListener('pointercancel', cancel);
      // hit-test the drop point before .es-dragging goes: on narrow screens the properties drawer steps aside while
      // dragging and must not catch the drop on its way back
      var target = ghost && !cancelled ? pageAt(P, ev.clientX, ev.clientY) : null;
      if (S.root) S.root.classList.remove('es-dragging');
      if (over) over.el.classList.remove('es-drop-ok');
      if (!ghost) return;
      if (ghost.parentNode) ghost.parentNode.removeChild(ghost);
      if (cancelled) { ed.suppressClick = false; return; }
      if (target) {
        var r = target.el.getBoundingClientRect();
        createField(P, ft.type, target, (ev.clientX - r.left) / r.width, (ev.clientY - r.top) / r.height);
      }
      setTimeout(function () { if (P.ed) P.ed.suppressClick = false; }, 0);
    }
    function up(ev) { end(ev, false); }
    function cancel(ev) { end(ev, true); }
    b.addEventListener('pointermove', move);
    b.addEventListener('pointerup', up);
    b.addEventListener('pointercancel', cancel);
  }

  function addFieldInView(P, type) {
    var ed = P.ed;
    if (!ed || !P.activeSigner) return;
    var pe = ed.cur || ed.pages[0];
    if (!pe) { toast('Add a document first.', 'warn'); return; }
    var ft = FT[type];
    var sr = canvasView(P), r = pe.el.getBoundingClientRect();
    var visTop = Math.max(r.top, sr.top), visBot = Math.min(r.bottom, sr.bottom);
    var cy = visBot > visTop ? ((visTop + visBot) / 2 - r.top) / r.height : 0.5;
    var w = ft.w / pe.size.w, hh = ft.h / pe.size.h;
    var pos = freeSpot(P, pe, 0.5 - w / 2, cy - hh / 2, w, hh);
    var f = createField(P, type, pe, pos.x, pos.y, true);
    var el = f && ed.fieldEls[f.id];
    if (!el) return;
    // phones: the properties sheet has just opened over the lower part of the canvas. Re-centre the new field in the
    // strip still in view rather than scroll the page away (the field was only placed 'in view' a moment ago).
    var v = canvasView(P), pr = pe.el.getBoundingClientRect(), fr = el.getBoundingClientRect();
    var vt = Math.max(pr.top, v.top), vb = Math.min(pr.bottom, v.bottom);
    if ((fr.top < vt || fr.bottom > vb) && vb - vt >= fr.height + 16) {
      var p2 = freeSpot(P, pe, pos.x, ((vt + vb) / 2 - pr.top) / pr.height - hh / 2, w, hh, f);
      f.x = round5(clamp(p2.x, 0, 1 - f.w)); f.y = round5(clamp(p2.y, 0, 1 - f.h));
      updateFieldEl(P, f); updateSizeReadout(P, f);
    }
    try { el.scrollIntoView({ block: 'nearest' }); } catch (e) { /* ignore */ }
    revealSel(P);
  }
  // Tapping the same field type twice mustn't stack two fields exactly on top of each other: keep the column and
  // try a row lower, then a row higher, and so on, until the spot is clear (falls back to the original spot).
  function freeSpot(P, pe, x, y, w, hh, skip) {
    x = clamp(x, 0, Math.max(0, 1 - w)); y = clamp(y, 0, Math.max(0, 1 - hh));
    var others = P.fields.filter(function (o) { return o !== skip && o.document_id === pe.doc.id && o.page === pe.n; });
    function clear(ty) {
      return ty >= 0 && ty <= 1 - hh && !others.some(function (o) { return x < o.x + o.w && o.x < x + w && ty < o.y + o.h && o.y < ty + hh; });
    }
    if (!others.length || clear(y)) return { x: x, y: y };
    var step = hh + 8 / pe.size.h;   // the field's height plus an 8 pt gap
    for (var k = 1; k <= 60; k++) {
      var ty = y + (k % 2 ? 1 : -1) * Math.ceil(k / 2) * step;
      if (clear(ty)) return { x: x, y: ty };
    }
    return { x: x, y: y };
  }

  /* ---- keep the selected field in sight when the properties panel overlays the canvas (≤1080px wide).
     Presentation only: it docks the side drawer away from the field, or scrolls the canvas so the field sits in the
     strip above the phone bottom sheet. Field data is untouched. */
  function propsOverlay(P) {
    var ed = P.ed;
    if (!ed || !ed.right || !P.sel) return null;
    var sr = ed.scroll.getBoundingClientRect(), rr = ed.right.getBoundingClientRect();
    if (!rr.width || !rr.height) return null;
    var ox = Math.min(rr.right, sr.right) - Math.max(rr.left, sr.left), oy = Math.min(rr.bottom, sr.bottom) - Math.max(rr.top, sr.top);
    if (ox <= 1 || oy <= 1) return null;   // its own column on wide screens: nothing is covered
    return { sheet: rr.width >= sr.width - 2, sr: sr, rr: rr };
  }
  function canvasView(P) {
    var sr = P.ed.scroll.getBoundingClientRect();
    var v = { top: sr.top, bottom: sr.bottom, left: sr.left, right: sr.right };
    var o = propsOverlay(P);
    if (o && o.sheet) v.bottom = Math.max(v.top, Math.min(v.bottom, o.rr.top));
    return v;
  }
  function revealSel(P, noScroll) {
    var ed = P.ed;
    var el = ed && P.sel && ed.fieldEls[P.sel];
    if (!el) return;
    var o = propsOverlay(P);
    if (!o) return;
    var fr = el.getBoundingClientRect();
    if (!o.sheet) {
      // side drawer (tablet / small laptop): dock it on whichever side covers less of the field and its resize handle
      var dw = o.rr.width, l = fr.left - 4, r = fr.right + 10;
      var covRight = Math.max(0, r - (o.sr.right - dw)), covLeft = Math.max(0, (o.sr.left + dw) - l);
      ed.root.classList.toggle('es-props-l', covLeft < covRight);
      return;
    }
    if (noScroll) return;   // mid-gesture: the canvas must not move under the pointer
    var top = o.sr.top + 8, bottom = Math.min(o.sr.bottom, o.rr.top) - 8;
    if (fr.top >= top && fr.bottom <= bottom) return;
    var d = (bottom - top < fr.height) ? fr.top - top : (fr.top + fr.bottom) / 2 - (top + bottom) / 2;
    ed.scroll.scrollTop += d;
  }

  function createField(P, type, pe, fx, fy, noReveal) {
    var ft = FT[type];
    var w = Math.min(1, ft.w / pe.size.w), hh = Math.min(1, ft.h / pe.size.h);
    var f = {
      id: 'fld_' + randHex(10), recipient_id: P.activeSigner, document_id: pe.doc.id, page: pe.n, type: type,
      x: round5(clamp(fx, 0, 1 - w)), y: round5(clamp(fy, 0, 1 - hh)), w: round5(w), h: round5(hh),
      required: type !== 'checkbox', label: null
    };
    P.fields.push(f);
    mountField(P, f);
    select(P, f.id, false, !!noReveal);
    fieldsChanged(P);
    return f;
  }

  function fieldText(f) {
    var ft = FT[f.type];
    if (f.label && ['text', 'company', 'title', 'name', 'email', 'date'].indexOf(f.type) >= 0) return f.label;
    return ft.short;
  }
  function fieldAria(P, f) {
    var r = recipById(P, f.recipient_id);
    return FT[f.type].label + ' field for ' + (r ? rName(r) : 'unassigned') + ', page ' + f.page + (f.required ? ', required' : ', optional');
  }
  function mountField(P, f) {
    var ed = P.ed;
    if (!ed) return null;
    var pe = ed.byKey[f.document_id + ':' + f.page];
    if (!pe) return null;
    var el = h('div', { class: 'es-fld es-fld-' + f.type, tabindex: '0', role: 'button', data: { id: f.id } },
      f.type === 'checkbox' ? icon('check', 'es-fld-ic') : null,
      h('span', { class: 'es-fld-t' }), h('span', { class: 'es-fld-h', 'aria-hidden': 'true' }));
    var id = f.id;
    el.addEventListener('pointerdown', function (e) { fieldPointer(P, e, id); });
    el.addEventListener('focus', function () { if (P.sel !== id) select(P, id, true); });
    el.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(P, id, true); focusProps(P); } });
    pe.layer.appendChild(el);
    ed.fieldEls[f.id] = el;
    updateFieldEl(P, f);
    return el;
  }
  function updateFieldEl(P, f) {
    var el = P.ed && P.ed.fieldEls[f.id];
    if (!el) return;
    var c = fieldColor(P, f);
    el.style.left = (f.x * 100) + '%';
    el.style.top = (f.y * 100) + '%';
    el.style.width = (f.w * 100) + '%';
    el.style.height = (f.h * 100) + '%';
    el.style.setProperty('--es-c', c);
    el.style.setProperty('--es-cf', rgba(c, 0.18));
    var t = el.querySelector('.es-fld-t');
    t.textContent = fieldText(f) + (f.required && f.type !== 'checkbox' ? ' *' : '');
    el.classList.toggle('es-sel', P.sel === f.id);
    el.classList.toggle('es-opt', !f.required);
    el.setAttribute('aria-label', fieldAria(P, f));
    el.setAttribute('aria-pressed', P.sel === f.id ? 'true' : 'false');
    var r = recipById(P, f.recipient_id);
    el.title = FT[f.type].label + ' · ' + (r ? rName(r) : 'unassigned') + (f.label ? ' · “' + f.label + '”' : '') + (f.required ? ' · required' : ' · optional');
  }
  function rebuildFieldEls(P) {
    var ed = P.ed;
    if (!ed) return;
    var hadFocus = document.activeElement && document.activeElement.classList && document.activeElement.classList.contains('es-fld');
    Object.keys(ed.fieldEls).forEach(function (id) { var el = ed.fieldEls[id]; if (el.parentNode) el.parentNode.removeChild(el); });
    ed.fieldEls = {};
    if (P.sel && !findField(P, P.sel)) P.sel = null;
    P.fields.forEach(function (f) { mountField(P, f); });
    if (hadFocus && P.sel && ed.fieldEls[P.sel]) ed.fieldEls[P.sel].focus({ preventScroll: true });
    renderSignerPicker(P);
    renderProps(P);
    updateCount(P);
  }
  function updateCount(P) {
    if (!P.ed) return;
    var n = P.fields.length;
    P.ed.countEl.textContent = plural(n, 'field');
  }
  function fieldsChanged(P) {
    P.fieldsVer++;
    P.savers.fields.schedule(800);
    updateCount(P);
    renderSignerPicker(P);
  }

  function select(P, id, fromFocus, midGesture) {
    var ed = P.ed;
    var prev = P.sel;
    P.sel = id;
    if (ed) {
      ed.root.classList.toggle('es-has-sel', !!id);
      [prev, id].forEach(function (x) { var f = x && findField(P, x); if (f) updateFieldEl(P, f); });
      if (id && !fromFocus && ed.fieldEls[id] && document.activeElement !== ed.fieldEls[id]) {
        try { ed.fieldEls[id].focus({ preventScroll: true }); } catch (e) { /* ignore */ }
      }
      renderProps(P);
      if (id) revealSel(P, midGesture);
    }
  }
  function focusProps(P) {
    if (!P.ed) return;
    var c = P.ed.right.querySelector('select, input');
    if (c) c.focus();
  }

  function fieldPointer(P, e, id) {
    if (e.button !== 0) return;
    var f = findField(P, id), ed = P.ed;
    if (!f || !ed) return;
    var el = ed.fieldEls[id], pe = ed.byKey[f.document_id + ':' + f.page];
    if (!el || !pe) return;
    var resize = !!(e.target.closest && e.target.closest('.es-fld-h'));
    if (P.sel !== id) select(P, id, false, true);
    else if (document.activeElement !== el) { try { el.focus({ preventScroll: true }); } catch (err) { /* ignore */ } }
    e.preventDefault();
    var rect = pe.el.getBoundingClientRect();
    var sx = e.clientX, sy = e.clientY, fx = f.x, fy = f.y, fw = f.w, fh = f.h, moved = false, pid = e.pointerId;
    try { el.setPointerCapture(pid); } catch (err) { /* ignore */ }
    el.classList.add(resize ? 'es-resizing' : 'es-moving');
    function move(ev) {
      if (ev.pointerId !== pid) return;
      if (!moved && Math.abs(ev.clientX - sx) + Math.abs(ev.clientY - sy) < 3) return;
      moved = true;
      var dx = (ev.clientX - sx) / rect.width, dy = (ev.clientY - sy) / rect.height;
      if (resize) {
        f.w = round5(clamp(fw + dx, MIN_FRAC, 1 - f.x));
        f.h = round5(clamp(fh + dy, MIN_FRAC, 1 - f.y));
      } else {
        f.x = round5(clamp(fx + dx, 0, 1 - f.w));
        f.y = round5(clamp(fy + dy, 0, 1 - f.h));
      }
      updateFieldEl(P, f);
      updateSizeReadout(P, f);
    }
    function end(ev) {
      if (ev.pointerId !== pid) return;
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', end);
      el.removeEventListener('pointercancel', end);
      el.classList.remove('es-resizing', 'es-moving');
      if (moved) fieldsChanged(P);
      if (P.sel === id) revealSel(P);   // once the finger is up, bring the field out from under the properties panel
    }
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', end);
    el.addEventListener('pointercancel', end);
  }

  function deleteField(P, id) {
    var i = P.fields.map(function (f) { return f.id; }).indexOf(id);
    if (i < 0) return;
    var f = P.fields[i];
    P.fields.splice(i, 1);
    var el = P.ed && P.ed.fieldEls[id];
    if (el && el.parentNode) el.parentNode.removeChild(el);
    if (P.ed) delete P.ed.fieldEls[id];
    if (P.sel === id) select(P, null);
    if (P.ed) { try { P.ed.scroll.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
    fieldsChanged(P);
    toast(FT[f.type].label + ' field deleted.', 'info', { action: { label: 'Undo', fn: function () {
      if (S.prep !== P || findField(P, f.id)) return;
      if (!recipById(P, f.recipient_id)) { toast('That recipient no longer exists.', 'warn'); return; }
      P.fields.splice(Math.min(i, P.fields.length), 0, f);
      if (P.ed) { mountField(P, f); select(P, f.id); }
      fieldsChanged(P);
    } } });
  }

  function editorKey(P, e) {
    var t = e.target;
    if (isTyping(t)) return;
    if (t && t !== document.body && S.root && !S.root.contains(t)) return;
    if (!P.ed) return;
    if (e.key === 'Escape' && P.sel) { consume(e); var id = P.sel; select(P, null); var el = P.ed.fieldEls[id]; if (el) el.focus({ preventScroll: true }); return; }
    var f = P.sel && findField(P, P.sel);
    if (!f) return;
    if (e.key === 'Delete' || e.key === 'Backspace') { consume(e); deleteField(P, f.id); return; }
    var dir = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[e.key];
    if (!dir) return;
    if (t && t.closest && (t.closest('.es-ed-rcps') || t.closest('.es-seg') || t.closest('.es-tabs'))) return;
    consume(e);
    var pe = P.ed.byKey[f.document_id + ':' + f.page];
    var size = pe ? pe.size : { w: 612, h: 792 };
    var step = e.shiftKey ? 10 : 1;   // PDF points
    f.x = round5(clamp(f.x + dir[0] * step / size.w, 0, 1 - f.w));
    f.y = round5(clamp(f.y + dir[1] * step / size.h, 0, 1 - f.h));
    updateFieldEl(P, f);
    updateSizeReadout(P, f);
    fieldsChanged(P);
  }

  function updateSizeReadout(P, f) {
    var ed = P.ed;
    if (!ed || !ed.sizeEl || P.sel !== f.id) return;
    var pe = ed.byKey[f.document_id + ':' + f.page];
    var size = pe ? pe.size : { w: 612, h: 792 };
    ed.sizeEl.textContent = Math.round(f.w * size.w) + ' × ' + Math.round(f.h * size.h) + ' pt';
    ed.posEl.textContent = 'Page ' + f.page + ' · ' + Math.round(f.x * size.w) + ', ' + Math.round(f.y * size.h) + ' pt';
  }

  function renderProps(P) {
    var ed = P.ed;
    if (!ed) return;
    var box = ed.right;
    box.textContent = '';
    ed.sizeEl = null; ed.posEl = null;
    var f = P.sel && findField(P, P.sel);
    if (!f) {
      box.appendChild(h('div', { class: 'es-props-h' }, h('div', { class: 'es-lbl', text: 'Field properties' })));
      box.appendChild(h('p', { class: 'es-hint', text: 'Select a field on the page to edit it.' }));
      var tips = h('ul', { class: 'es-tips' },
        h('li', { text: 'Drag fields from the left onto the page.' }),
        h('li', { text: 'Drag a field to move it; drag its corner to resize.' }),
        h('li', { text: 'Arrow keys nudge the selected field (Shift = 10 pt).' }),
        h('li', { text: 'Delete or Backspace removes it; Esc deselects.' }));
      box.appendChild(tips);
      var signers = signersOf(P);
      if (signers.length) {
        var sum = h('div', { class: 'es-props-sum' }, h('div', { class: 'es-lbl', text: 'Fields per signer' }));
        signers.forEach(function (s) {
          var fs = P.fields.filter(function (x) { return x.recipient_id === s.id; });
          var hasSig = fs.some(function (x) { return x.type === 'signature'; });
          sum.appendChild(h('div', { class: 'es-props-row', style: { '--es-c': recipColor(s) } }, h('span', { class: 'es-r-dot', 'aria-hidden': 'true' }),
            h('span', { class: 'es-grow es-ell', text: rName(s) }),
            h('span', { class: fs.length ? (hasSig ? 'es-dimtxt' : 'es-warn-t') : 'es-danger-t', text: fs.length ? plural(fs.length, 'field') + (hasSig ? '' : ' · no signature') : 'none yet' })));
        });
        box.appendChild(sum);
      }
      return;
    }
    var ft = FT[f.type];
    box.appendChild(h('div', { class: 'es-props-h' }, h('div', { class: 'es-props-type', style: { '--es-c': fieldColor(P, f) } }, icon(ft.icon), h('span', { text: ft.label })),
      btn('Deselect', { icon: 'x', iconOnly: true, kind: 'quiet', size: 's', onClick: function () { select(P, null); } })));

    var sel = h('select', { class: 'es-in es-sel' }, signersOf(P).map(function (s) { return h('option', { value: s.id, text: rName(s) }); }));
    if (!recipById(P, f.recipient_id)) sel.appendChild(h('option', { value: f.recipient_id || '', text: '(removed recipient)' }));
    sel.value = f.recipient_id || '';
    sel.addEventListener('change', function () {
      f.recipient_id = sel.value;
      updateFieldEl(P, f);
      box.querySelector('.es-props-type').style.setProperty('--es-c', fieldColor(P, f));
      fieldsChanged(P);
    });
    box.appendChild(field('Assigned to', sel));

    var reqId = uid('req');
    var req = h('input', { type: 'checkbox', id: reqId, class: 'es-cbx', checked: !!f.required });
    req.addEventListener('change', function () { f.required = req.checked; updateFieldEl(P, f); fieldsChanged(P); });
    box.appendChild(h('div', { class: 'es-fieldset' }, h('label', { class: 'es-check', for: reqId }, req, h('span', { text: 'Required field' })),
      f.type === 'date_signed' ? h('div', { class: 'es-hint', text: 'Filled automatically with the signing date.' }) :
        (f.type === 'name' || f.type === 'email') ? h('div', { class: 'es-hint', text: 'Pre-filled from the recipient’s details.' }) : null));

    var lab = h('input', { class: 'es-in', type: 'text', maxlength: '80', value: f.label || '', placeholder: f.type === 'checkbox' ? 'e.g. I agree to the terms' : 'e.g. ' + ft.label });
    lab.addEventListener('input', function () { f.label = lab.value || null; updateFieldEl(P, f); fieldsChanged(P); });
    box.appendChild(field('Label / tooltip', lab, 'Shown to the signer as a placeholder or hint.'));

    ed.sizeEl = h('div', { class: 'es-mono' });
    ed.posEl = h('div', { class: 'es-mono es-dimtxt' });
    box.appendChild(h('div', { class: 'es-fieldset' }, h('div', { class: 'es-lbl', text: 'Size & position' }), ed.sizeEl, ed.posEl,
      h('button', { type: 'button', class: 'es-linkbtn', text: 'Reset to default size', on: { click: function () {
        var pe = ed.byKey[f.document_id + ':' + f.page];
        var size = pe ? pe.size : { w: 612, h: 792 };
        f.w = round5(Math.min(1, ft.w / size.w)); f.h = round5(Math.min(1, ft.h / size.h));
        f.x = round5(clamp(f.x, 0, 1 - f.w)); f.y = round5(clamp(f.y, 0, 1 - f.h));
        updateFieldEl(P, f); updateSizeReadout(P, f); fieldsChanged(P);
      } } })));
    updateSizeReadout(P, f);

    box.appendChild(h('div', { class: 'es-props-acts' },
      btn('Duplicate', { icon: 'copy', size: 's', onClick: function () {
        var pe = ed.byKey[f.document_id + ':' + f.page];
        if (!pe) return;
        var nf = { id: 'fld_' + randHex(10), recipient_id: f.recipient_id, document_id: f.document_id, page: f.page, type: f.type,
          x: round5(clamp(f.x + 0.02, 0, 1 - f.w)), y: round5(clamp(f.y + 0.02, 0, 1 - f.h)), w: f.w, h: f.h, required: f.required, label: f.label };
        P.fields.push(nf); mountField(P, nf); select(P, nf.id); fieldsChanged(P);
      } }),
      btn('Delete field', { icon: 'trash', size: 's', kind: 'danger', onClick: function () { deleteField(P, f.id); } })));
  }

  /* ---- Step 4: review & send */
  function computeIssues(P) {
    var errors = [], warns = [];
    var docs = P.env.documents;
    if (!docs.length) errors.push({ text: 'Add at least one document.', step: 1 });
    var rows = P.recips.filter(function (r) { return !isBlankNew(r); });
    var invalid = rows.filter(hasErrors);
    if (invalid.length) errors.push({ text: plural(invalid.length, 'recipient has', 'recipients have') + ' missing or invalid details.', step: 2 });
    var signers = rows.filter(function (r) { return r.role === 'signer'; });
    if (!signers.length) errors.push({ text: 'Add at least one recipient who needs to sign.', step: 2 });
    signers.forEach(function (s) {
      var fs = s.id ? P.fields.filter(function (f) { return f.recipient_id === s.id; }) : [];
      if (!fs.length) errors.push({ text: rName(s) + ' has no fields yet — place at least one (usually a Signature).', step: 3 });
      else if (!fs.some(function (f) { return f.type === 'signature' || f.type === 'initials'; })) warns.push({ text: rName(s) + ' has no Signature or Initials field.', step: 3 });
    });
    if (!str(P.env.title).trim()) errors.push({ text: 'Add a subject.', step: 4 });
    if (willEmail(P) && str(P.env.sender_email).trim() && !mailable(P.env.sender_email)) errors.push({ text: 'Your email address isn’t one ' + B() + ' can email (use a plain address like name@company.com).', step: 4 });
    if (willEmail(P) && !str(P.env.sender_name).trim()) errors.push({ text: 'Add your name as the sender — recipients see it in the email.', step: 4 });
    if (P.env.expires_at) {
      var d = parseDate(P.env.expires_at);
      if (d && d.getTime() < Date.now()) errors.push({ text: 'The expiry date is in the past.', step: 4 });
    }
    var seen = {}, dup = [];
    rows.forEach(function (r) { var k = lc(r.email); if (k && seen[k] && dup.indexOf(r.email) < 0) dup.push(r.email.trim()); seen[k] = 1; });
    if (dup.length) warns.push({ text: 'The same email is used more than once (' + dup.join(', ') + '). Each gets a separate link.', step: 2 });
    var noMail = S.cfg && !S.cfg.email_codes ? rows.filter(function (r) { return r.email_code; }) : [];
    if (noMail.length) warns.push({ text: 'An email code is on for ' + noMail.map(rName).join(', ') + ', but no outgoing mail server is set up on this server — the code can’t be sent, so the link won’t open.', step: 2 });
    if (P.uploads.some(function (u) { return u.status === 'error'; })) warns.push({ text: 'Some uploads failed and aren’t part of the envelope.', step: 1 });
    if (P.savers.recips.failed || P.savers.fields.failed || P.savers.meta.failed) warns.push({ text: 'Some changes haven’t been saved yet — they’ll be saved before sending.', step: null });
    return { errors: errors, warns: warns };
  }

  function renderReviewStep(P, body) {
    var grid = h('div', { class: 'es-review' });
    var form = h('div', { class: 'es-card es-rv-form' });
    form.appendChild(h('h3', { class: 'es-h3', text: 'Message to recipients' }));
    var titleIn = h('input', { class: 'es-in', type: 'text', maxlength: '200', value: P.env.title || '', required: true });
    var titleErr = h('div', { class: 'es-err' });
    var titleCount = h('span', { class: 'es-counter' });
    function onTitle() {
      P.env.title = titleIn.value;
      titleCount.textContent = titleIn.value.length + '/200';
      titleErr.textContent = titleIn.value.trim() ? '' : 'A subject is required.';
      if (titleIn.value.trim()) titleIn.removeAttribute('aria-invalid'); else titleIn.setAttribute('aria-invalid', 'true');
      setWizardTitle(P);
      P.savers.meta.schedule();
      refreshIssues();
    }
    titleIn.addEventListener('input', onTitle);
    form.appendChild(field('Subject', titleIn, null, h('div', { class: 'es-fmeta' }, titleErr, titleCount)));
    titleCount.textContent = titleIn.value.length + '/200';

    var msgIn = h('textarea', { class: 'es-in es-ta', rows: '5', maxlength: '2000', placeholder: 'Add a short message for everyone (optional).', value: P.env.message || '' });
    var msgCount = h('span', { class: 'es-counter', text: msgIn.value.length + '/2000' });
    msgIn.addEventListener('input', function () { P.env.message = msgIn.value; msgCount.textContent = msgIn.value.length + '/2000'; P.savers.meta.schedule(); });
    form.appendChild(field('Message', msgIn, null, h('div', { class: 'es-fmeta' }, h('span'), msgCount)));

    var sn = h('input', { class: 'es-in', type: 'text', maxlength: '120', value: P.env.sender_name || '', placeholder: 'Your name or company' });
    P.ui.senderIn = sn;
    P.stepOff.push(function () { P.ui.senderIn = null; P.ui.sendBtn = null; P.ui.issuesEl = null; });
    sn.addEventListener('input', function () { P.env.sender_name = sn.value; P.savers.meta.schedule(); if (P.ui.refreshIssues) P.ui.refreshIssues(); });
    form.appendChild(field('Sender name', sn, 'Shown to recipients as who sent the envelope.'));

    // only drafts that can email their links: the choice to email them (off = share them yourself, as before) and
    // the sender's own email (Reply-To on what recipients get, and where the server tells them about signatures)
    if (P.env.email_available && cfg().email_links) {
      P.ui.notifyShown = true;
      P.stepOff.push(function () { P.ui.notifyShown = false; });
      if (typeof P.notify !== 'boolean') P.notify = true;
      var nid = uid('ntf');
      var nIn = h('input', { type: 'checkbox', id: nid, class: 'es-cbx', checked: P.notify });
      var nHint = h('div', { class: 'es-hint', id: uid('ntfh') });
      var se = h('input', { class: 'es-in', type: 'email', maxlength: '254', value: P.env.sender_email || '', placeholder: 'you@example.com', autocomplete: 'email' });
      var seErr = h('div', { class: 'es-err' });
      var seSug = h('div', { class: 'es-hint' });
      var seField = field('Your email (optional)', se, 'When recipients reply, it comes here. ' + B() + ' also tells you here when someone signs or declines, and when everything is complete.', h('div', null, seErr, seSug));
      var nText = function () {
        nHint.textContent = P.notify
          ? B() + ' emails each person their own link' + (cfg().email_from ? ' from ' + cfg().email_from : '') + '. If people sign in order, each one is emailed when it’s their turn. At the end everyone is emailed the signed copy, or a link to it.'
          : 'No emails: after sending, you copy each link and share it yourself.';
        seField.hidden = !P.notify;
      };
      var suggest = function () {                   // the address this account used last time: one click, never automatic
        seSug.textContent = '';
        var last = rememberedSenderEmail();
        if (last && mailable(last) && !str(se.value).trim()) {
          seSug.appendChild(h('button', { type: 'button', class: 'es-linkbtn', text: 'Use ' + last, on: { click: function () {
            se.value = last; P.env.sender_email = last; seSug.textContent = ''; P.savers.meta.schedule(); refreshIssues();
          } } }));
        }
      };
      se.addEventListener('input', function () {
        P.env.sender_email = se.value;
        var v = se.value.trim(), bad = v && !mailable(v);
        seErr.textContent = bad ? 'Use a plain address like name@company.com.' : '';
        if (bad) se.setAttribute('aria-invalid', 'true'); else se.removeAttribute('aria-invalid');
        if (!v) rememberSenderEmail('');
        suggest();
        P.savers.meta.schedule();
        refreshIssues();
      });
      nIn.setAttribute('aria-describedby', nHint.id);
      nIn.addEventListener('change', function () { P.notify = nIn.checked; nText(); if (P.ui.sendNote) P.ui.sendNote(); refreshIssues(); P.savers.meta.schedule(); });
      form.appendChild(h('div', { class: 'es-fieldset es-ec' }, h('label', { class: 'es-check', for: nid }, nIn, h('span', { text: 'Email the signing links for me' })), nHint));
      form.appendChild(seField);
      nText();
      suggest();
    }

    var cur = P.env.expires_at ? String(P.env.expires_at).slice(0, 10) : '';
    var exp = h('input', { class: 'es-in es-in-date', type: 'date', min: todayISO(), value: cur });
    var clearExp = h('button', { type: 'button', class: 'es-linkbtn', text: 'No expiry', hidden: !cur });
    exp.addEventListener('change', function () {
      P.env.expires_at = exp.value ? exp.value + 'T23:59:59Z' : null;
      clearExp.hidden = !exp.value;
      P.savers.meta.schedule(200);
      refreshIssues();
    });
    clearExp.addEventListener('click', function () { exp.value = ''; P.env.expires_at = null; clearExp.hidden = true; P.savers.meta.schedule(200); refreshIssues(); exp.focus(); });
    exp.id = uid('exp');
    var expField = field('Expires on (optional)', h('div', { class: 'es-inline' }, exp, clearExp), 'Links stop working at the end of this day (UTC). Leave empty for no expiry.');
    expField.querySelector('label').setAttribute('for', exp.id);
    form.appendChild(expField);
    grid.appendChild(form);

    // summary
    var side = h('div', { class: 'es-rv-side' });
    P.ui.issuesEl = h('div', { class: 'es-issues' });
    side.appendChild(P.ui.issuesEl);

    var sum = h('div', { class: 'es-card es-rv-sum' });
    var docs = P.env.documents;
    var pages = docs.reduce(function (a, d) { return a + docPages(d).length; }, 0);
    sum.appendChild(h('div', { class: 'es-rv-sec' }, h('div', { class: 'es-rv-h' }, h('span', { class: 'es-lbl', text: 'Documents' }),
      h('button', { type: 'button', class: 'es-linkbtn', text: 'Edit', 'aria-label': 'Edit documents', on: { click: function () { goStep(P, 1); } } })),
    docs.length ? h('ul', { class: 'es-rv-list' }, docs.map(function (d) {
      return h('li', null, icon('doc'), h('span', { class: 'es-grow es-ell', text: d.name || 'Document' }), h('span', { class: 'es-dimtxt', text: plural(docPages(d).length, 'page') }));
    })) : h('p', { class: 'es-dimtxt', text: 'No documents.' }),
    docs.length ? h('div', { class: 'es-hint', text: plural(docs.length, 'document') + ' · ' + plural(pages, 'page') + ' in total' }) : null));

    var rows = P.recips.filter(function (r) { return !isBlankNew(r); }).slice();
    rows.sort(function (a, b) { return (P.sequential ? a.routing_order - b.routing_order : 0); });
    sum.appendChild(h('div', { class: 'es-rv-sec' }, h('div', { class: 'es-rv-h' }, h('span', { class: 'es-lbl', text: 'Recipients · ' + (P.sequential ? 'in signing order' : 'all at once') }),
      h('button', { type: 'button', class: 'es-linkbtn', text: 'Edit', 'aria-label': 'Edit recipients', on: { click: function () { goStep(P, 2); } } })),
    rows.length ? h('ul', { class: 'es-rv-list es-rv-rcps' }, rows.map(function (r) {
      var fs = r.id ? P.fields.filter(function (f) { return f.recipient_id === r.id; }) : [];
      var counts = {};
      fs.forEach(function (f) { counts[f.type] = (counts[f.type] || 0) + 1; });
      var cstr = Object.keys(counts).map(function (k) { return counts[k] + ' ' + FT[k].label.toLowerCase(); }).join(', ');
      return h('li', { style: { '--es-c': recipColor(r) } },
        P.sequential ? h('span', { class: 'es-ord', text: String(r.routing_order) }) : null,
        h('span', { class: 'es-r-dot', 'aria-hidden': 'true' }),
        h('div', { class: 'es-grow es-rv-rcp' }, h('div', { class: 'es-ell' }, h('strong', { text: rName(r) }), h('span', { class: 'es-dimtxt', text: ' · ' + r.email })),
          h('div', { class: 'es-hint' }, ROLE_LABEL[r.role] + (r.role === 'signer' ? ' · ' + (fs.length ? plural(fs.length, 'field') + ' (' + cstr + ')' : 'no fields') : '') +
            ((r.access_code_set && r.codeAction !== 'clear') || r.codeAction === 'set' ? ' · access code' : '') +
            (r.email_code ? ' · email code' : ''))));
    })) : h('p', { class: 'es-dimtxt', text: 'No recipients.' })));
    side.appendChild(sum);
    var noteP = h('p');
    P.ui.sendNote = function () {
      noteP.textContent = willEmail(P)
        ? 'After you send, ' + B() + ' creates a private signing link for each recipient and emails it to them. You can still copy any link yourself. Documents and fields are locked once sent.'
        : 'After you send, ' + B() + ' creates a private signing link for each recipient. ' + B() + ' doesn’t email the links — you copy each link (or open it in your mail app) and share it. Documents and fields are locked once sent.';
    };
    P.ui.sendNote();
    P.stepOff.push(function () { P.ui.sendNote = null; });
    side.appendChild(h('div', { class: 'es-note' }, icon('info'), noteP));
    grid.appendChild(side);
    body.appendChild(grid);

    function refreshIssues() {
      var el = P.ui.issuesEl;
      if (!el) return;
      el.textContent = '';
      var is = computeIssues(P);
      if (P.sendProblems && P.sendProblems.length) {
        el.appendChild(callout('red', 'alert', 'The envelope couldn’t be sent', null,
          h('ul', { class: 'es-co-list' }, P.sendProblems.map(function (p) { return h('li', { text: p }); }))));
      }
      if (is.errors.length) {
        el.appendChild(callout('red', 'alert', 'Before you can send', null, h('ul', { class: 'es-co-list' }, is.errors.map(issueLi))));
      }
      if (is.warns.length) {
        el.appendChild(callout('amber', 'info', 'Worth checking', null, h('ul', { class: 'es-co-list' }, is.warns.map(issueLi))));
      }
      if (!is.errors.length && !(P.sendProblems && P.sendProblems.length)) {
        el.appendChild(callout('green', 'check', 'Ready to send', 'Everything required is in place.'));
      }
      if (P.ui.sendBtn) P.ui.sendBtn.disabled = is.errors.length > 0;
    }
    function issueLi(i) {
      return h('li', null, i.text + ' ', i.step && i.step !== 4 ? h('button', { type: 'button', class: 'es-linkbtn', text: 'Fix', 'aria-label': 'Fix: ' + i.text,
        on: { click: function () { goStep(P, i.step); } } }) : null);
    }
    P.ui.refreshIssues = refreshIssues;
    refreshIssues();
  }

  /** Will sending this draft email the links? (only drafts created since the server could email, and only if chosen) */
  function willEmail(P) { return !!(P && P.env && P.env.email_available && cfg().email_links && P.notify !== false); }
  function sendEnvelope(P, b) {
    var is = computeIssues(P);
    if (is.errors.length) { if (P.ui.refreshIssues) P.ui.refreshIssues(); return; }
    var rows = P.recips.filter(function (r) { return !isBlankNew(r); });
    var mailing = willEmail(P);
    confirmDialog('Send “' + (str(P.env.title).trim() || DEFAULT_TITLE) + '” to ' + plural(rows.length, 'recipient') + '?\n\n' +
      (mailing ? B() + ' will email each recipient their own private signing link (people signing in order get theirs when it’s their turn). Documents, recipients’ roles and fields are locked after sending.'
        : B() + ' will generate a private signing link for each recipient. The links aren’t emailed automatically — you share them yourself. Documents, recipients’ roles and fields are locked after sending.'),
    { title: 'Send envelope', okLabel: 'Send envelope' }).then(function (ok) {
      if (!ok) return;
      setBusy(b, true);
      P.sendProblems = null;
      flushAll(P).then(function () {
        if (S.prep !== P) return null;
        if (prepDirty(P)) {
          setBusy(b, false);
          var bl = P.savers.recips.blocked || P.savers.meta.blocked;
          toast(bl ? bl + ' before sending.' : 'Some changes couldn’t be saved — fix that before sending.', 'err');
          return null;
        }
        return EP.send(P.eid, P.env.email_available ? mailing : undefined).then(function (env) {
          if (S.prep !== P) return;
          S.prep = null;
          S.sentBanner = P.eid;
          if (env && env.id && Array.isArray(env.recipients)) goDetail(env);
          else openEnvelope(P.eid);
        }, function (err) {
          setBusy(b, false);
          if (S.prep !== P) return;
          if (err.status === 422 || (err.problems && err.problems.length)) {
            P.sendProblems = err.problems && err.problems.length ? err.problems : [err.detail];
            if (P.ui.refreshIssues) P.ui.refreshIssues();
            if (P.ui.body) P.ui.body.scrollTop = 0;
            toast('The envelope couldn’t be sent — see the problems listed.', 'err');
          } else toast('Couldn’t send: ' + errMsg(err), 'err');
        });
      });
    });
  }

  /* ================================================================== ENVELOPE DETAIL */
  function goDetail(env) {
    S.prep = null;
    route(env.id);
    S.det = { env: env, eid: env.id, busy: false, sig: detailSig(env), banner: S.sentBanner === env.id };
    S.sentBanner = null;
    setTitle('E-Sign · ' + (env.title || DEFAULT_TITLE));
    setView('detail', function (el) { renderDetail(el); });
    var timer = setInterval(function () {
      if (S.view !== 'detail' || !S.det) return;
      if (document.visibilityState !== 'visible') return;
      var mailing = arr(S.det.env.recipients).some(function (r) { return r.email_state === 'queued'; });
      if (S.det.env.status !== 'sent' && !mailing) return;
      refreshDetail(false);
    }, 10000);
    onViewDispose(function () { clearInterval(timer); });
  }
  function detailSig(env) {
    try {
      return JSON.stringify([env.status, env.updated_at, env.current_order, arr(env.events).length, env.integrity && env.integrity.ok,
        arr(env.recipients).map(function (r) {
          return [r.id, r.status, r.view_count, r.notified_at, r.link, r.name, r.email, r.access_code_set, r.note, r.signed_at, r.declined_at,
            r.email_code, r.email_verified_at,
            r.email_state || null, r.emailed_at || null, r.email_error || null, r.link_emailed_at || null,
            !!(r.link_emailed_at && parseDate(r.emailed_at) && Date.now() - parseDate(r.emailed_at).getTime() < REMIND_GAP_MS)];
        })]);
    } catch (e) { return String(Math.random()); }
  }
  function refreshDetail(force) {
    var D = S.det;
    if (!D || D.busy) return Promise.resolve();
    D.busy = true;
    return EP.get(D.eid).then(function (env) {
      D.busy = false;
      if (S.det !== D || !env || !env.id) return;
      var sig = detailSig(env);
      if (!force && sig === D.sig) return;
      D.env = env; D.sig = sig;
      if (env.status === 'draft') { goPrepare(env); return; }
      rerenderDetail();
    }, function (err) {
      D.busy = false;
      if (force && S.det === D) toast('Couldn’t refresh: ' + errMsg(err), 'err');
    });
  }
  function rerenderDetail() {
    var v = S.viewEl;
    if (!v || S.view !== 'detail') return;
    var top = v.scrollTop;
    var ae = document.activeElement;
    var fk = ae && v.contains(ae) && ae.getAttribute('data-fk');
    v.textContent = '';
    renderDetail(v);
    v.scrollTop = top;
    if (fk) {
      var n = v.querySelector('[data-fk="' + (window.CSS && CSS.escape ? CSS.escape(fk) : fk) + '"]');
      if (n) { try { n.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
    }
  }
  function replaceRecipient(r) {
    var D = S.det;
    if (!D || !r || !r.id) return;
    D.env.recipients = arr(D.env.recipients).map(function (x) { return x.id === r.id ? Object.assign({}, x, r) : x; });
    D.sig = detailSig(D.env);
    rerenderDetail();
    refreshDetail(false);
  }
  function fk(el, key) { el.setAttribute('data-fk', key); return el; }

  function renderDetail(el) {
    var D = S.det, env = D.env;
    setTitle('E-Sign · ' + (env.title || DEFAULT_TITLE));
    var inProgress = env.status === 'sent';
    var wrap = h('div', { class: 'es-page es-det' });
    var refreshB = btn('Refresh', { icon: 'refresh', iconOnly: true, kind: 'quiet', onClick: function (e, b) {
      setBusy(b, true); refreshDetail(true).then(function () { setBusy(b, false); });
    } });
    fk(refreshB, 'refresh');
    wrap.appendChild(h('div', { class: 'es-topbar' }, backOut(), h('div', { class: 'es-grow' }),
      inProgress ? h('span', { class: 'es-live', title: 'Updates automatically every 10 seconds' }, h('span', { class: 'es-live-dot', 'aria-hidden': 'true' }), 'Live') : null, refreshB));

    if (D.banner && D.env && D.env.status === 'sent') {   /* the 'share your links' hint only matters while in progress */
      wrap.appendChild(h('div', { class: 'es-banner', role: 'status' }, icon('send'),
        mailOn(D.env)
          ? h('div', { class: 'es-grow' }, h('strong', { text: 'Envelope sent — ' + B() + ' is emailing each recipient their link.' }),
            h('div', { class: 'es-hint', text: 'If people sign in order, each one is emailed when it’s their turn. Each recipient below shows “Emailed” once their email has gone out.' }))
          : h('div', { class: 'es-grow' }, h('strong', { text: 'Envelope sent — now share each signer’s link (' + B() + ' doesn’t email the links).' }),
            h('div', { class: 'es-hint', text: 'Use “Copy link” or “Email from my mail app” on each recipient below, then “Mark as shared” so you can track it.' })),
        btn('Dismiss', { icon: 'x', iconOnly: true, kind: 'quiet', size: 's', onClick: function () { D.banner = false; rerenderDetail(); } })));
    }

    // header
    var meta = h('div', { class: 'es-det-meta' });
    function mi(label, val, title) { if (val) meta.appendChild(h('span', { class: 'es-mi', title: title || null }, h('span', { class: 'es-dimtxt', text: label + ' ' }), val)); }
    mi('From', env.sender_name);
    if (mailOn(env)) mi('Replies to', env.sender_email);
    mi('Sent', fmtDateTime(env.sent_at), fmtFull(env.sent_at));
    mi('Completed', fmtDateTime(env.completed_at), fmtFull(env.completed_at));
    mi('Voided', fmtDateTime(env.voided_at), fmtFull(env.voided_at));
    if (env.expires_at) mi(env.status === 'expired' ? 'Expired' : 'Expires', fmtDate(env.expires_at), fmtFull(env.expires_at));
    meta.appendChild(h('span', { class: 'es-mi es-mono es-dimtxt', title: 'Envelope ID', text: env.id }));

    var acts = h('div', { class: 'es-det-acts' });
    if (env.status === 'completed') {
      acts.appendChild(fk(btn('Download signed PDF', { icon: 'download', kind: 'primary', onClick: function (e, b) { downloadEnvelope(env, 'combined', b); } }), 'dl'));
    } else {
      acts.appendChild(fk(btn(inProgress ? 'Download current state' : 'Download PDF', { icon: 'download', onClick: function (e, b) { downloadEnvelope(env, 'combined', b); } }), 'dl'));
    }
    acts.appendChild(fk(btn('Certificate', { icon: 'shield', title: 'Certificate of Completion', onClick: function (e, b) { downloadEnvelope(env, 'certificate', b); } }), 'cert'));
    acts.appendChild(fk(btn('Duplicate', { icon: 'copy', onClick: function (e, b) { duplicateEnvelope(env.id, b); } }), 'dup'));
    if (inProgress) {
      acts.appendChild(fk(btn('Void', { icon: 'ban', kind: 'danger', onClick: function (e, b) {
        voidEnvelope(env, b).then(function (res) {
          if (!res) return;
          if (res && res.id && Array.isArray(res.recipients)) { S.det.env = res; S.det.sig = detailSig(res); rerenderDetail(); }
          else refreshDetail(true);
        });
      } }), 'void'));
    }
    wrap.appendChild(h('header', { class: 'es-det-head' },
      h('div', { class: 'es-det-tt' }, h('div', { class: 'es-det-ttl' }, h('h2', { class: 'es-h1', text: env.title || DEFAULT_TITLE }), envChip(env.status)), meta),
      acts));

    // status callout
    var recips = arr(env.recipients).slice().sort(function (a, b) { return (a.routing_order || 0) - (b.routing_order || 0); });
    var byId = {};
    recips.forEach(function (r) { byId[r.id] = r; });
    if (env.status === 'declined') {
      var dec = env.decline || {};
      var who = byId[dec.recipient_id] || recips.filter(function (r) { return r.status === 'declined'; })[0];
      wrap.appendChild(callout('red', 'ban', 'Declined' + (who ? ' by ' + rName(who) : '') + (dec.at ? ' · ' + fmtDateTime(dec.at) : ''),
        (dec.reason || (who && who.decline_reason)) ? '“' + (dec.reason || who.decline_reason) + '”' : 'No reason given.'));
    } else if (env.status === 'voided') {
      wrap.appendChild(callout('red', 'ban', 'Voided' + (env.voided_at ? ' · ' + fmtDateTime(env.voided_at) : ''), env.void_reason ? 'Reason: ' + env.void_reason : null));
    } else if (env.status === 'expired') {
      wrap.appendChild(callout('amber', 'clock', 'This envelope expired' + (env.expires_at ? ' on ' + fmtDate(env.expires_at) : ''), 'Signing links no longer work. Duplicate it to send again.'));
    } else if (env.status === 'completed') {
      wrap.appendChild(callout('green', 'check', 'Completed' + (env.completed_at ? ' · ' + fmtDateTime(env.completed_at) : ''),
        'Everyone has finished. The signed PDF includes a Certificate of Completion' + (env.final && env.final.sha256 ? ' (SHA-256 ' + String(env.final.sha256).slice(0, 16) + '…).' : '.'),
        sealStatus(env)));
    } else if (inProgress) {
      var failed = mailOn(env) ? recips.filter(function (r) { return linkUnshared(env, r) && r.email_state === 'failed'; }) : [];
      if (failed.length) {
        var ccOnly = failed.every(function (r) { return r.role === 'cc'; });
        wrap.appendChild(callout('red', 'mail', failed.length === 1 ? 'We couldn’t email ' + rName(failed[0]) : 'We couldn’t email ' + failed.length + ' recipients',
          (mailLive(env) ? 'Check the address (Correct details sends a new link), ' + (ccOnly ? 'regenerate the link (' + B() + ' emails the new one)' : 'email it again') + ', or copy'
            : 'Copy') + ' the link and send it yourself: ' + failed.map(rName).join(', ') + '.'));
      }
      var ready = recips.filter(function (r) { return r.link && linkUnshared(env, r) && r.email_state !== 'failed'; });
      if (ready.length) {
        wrap.appendChild(callout('amber', 'link', ready.length === 1 ? 'A signing link is ready to share' : ready.length + ' signing links are ready to share',
          'Share with ' + ready.map(rName).join(', ') + ', then mark ' + (ready.length === 1 ? 'it' : 'them') + ' as shared.'));
      }
    }

    // routing timeline
    wrap.appendChild(h('h3', { class: 'es-h3 es-sec-t', text: 'Routing' }));
    wrap.appendChild(routingTimeline(env, recips));

    // recipients
    wrap.appendChild(h('h3', { class: 'es-h3 es-sec-t', text: 'Recipients' }));
    var cards = h('div', { class: 'es-rcards' });
    recips.forEach(function (r) { cards.appendChild(recipientCard(env, r)); });
    if (!recips.length) cards.appendChild(h('p', { class: 'es-dimtxt', text: 'No recipients.' }));
    wrap.appendChild(cards);

    // documents
    wrap.appendChild(h('h3', { class: 'es-h3 es-sec-t', text: 'Documents' }));
    var docs = normDocs(env.documents);
    var dl = h('div', { class: 'es-card es-ddocs' });
    docs.forEach(function (d) {
      dl.appendChild(h('div', { class: 'es-ddoc' }, icon('doc'),
        h('div', { class: 'es-grow es-ddoc-i' }, h('div', { class: 'es-ell', text: d.name || 'Document' }),
          h('div', { class: 'es-hint' }, plural(docPages(d).length, 'page') + (d.size ? ' · ' + fmtSize(d.size) : '') +
            (sourceLabel(d) ? ' · converted from ' + sourceLabel(d) : ''),
            d.sha256_original ? h('span', { class: 'es-mono', title: 'SHA-256 of the original upload: ' + d.sha256_original, text: ' · SHA-256 ' + String(d.sha256_original).slice(0, 12) + '…' }) : null)),
        h('div', { class: 'es-ddoc-a' },
          fk(btn('Original', { icon: 'download', size: 's', title: sourceLabel(d) ? 'Download the original ' + sourceLabel(d) + ' file exactly as uploaded (signers see the converted PDF)' : 'Download the original file exactly as uploaded', onClick: function (e, b) {
            runDownload(function () { return EP.docFile(env.id, d.id, 'original'); }, d.name || 'document.pdf', b);
          } }), 'do-' + d.id),
          env.status !== 'completed' ? fk(btn('Current', { icon: 'download', size: 's', title: 'Download this document with the signatures collected so far', onClick: function (e, b) {
            runDownload(function () { return EP.docFile(env.id, d.id, 'current'); }, baseName(d.name || 'document') + '-current.pdf', b);
          } }), 'dc-' + d.id) : null)));
    });
    if (!docs.length) dl.appendChild(h('p', { class: 'es-dimtxt', text: 'No documents.' }));
    wrap.appendChild(dl);

    // audit trail
    wrap.appendChild(auditSection(env, byId));
    wrap.appendChild(h('p', { class: 'es-legal', text: legalText(env) }));
    el.appendChild(wrap);
  }

  /** The footnote under an envelope: accurate for this envelope when it is complete, else for this server's setup. */
  function legalText(env) {
    var base = 'This service captures simple electronic signatures (SES) with intent, consent and a hash-chained audit trail (ESIGN Act / UETA / eIDAS SES).';
    var seal = env.status === 'completed' && env.final ? env.final.seal : null;
    var sealed = seal ? !!seal.sealed : (env.status !== 'completed' && cfg().seal.configured);
    if (!sealed) return base + ' It is not a qualified electronic signature (QES), and the PDF is not PAdES-sealed.';
    var stamped = seal ? seal.level === 'PAdES-B-T' : true;
    return base + (env.status === 'completed' ? ' The completed PDF carries' : ' Completed PDFs carry') + ' a PAdES digital seal' +
      (stamped ? ' with an RFC 3161 timestamp' : '') + ', which shows the file hasn’t changed since it was sealed. ' +
      'The signatures themselves remain simple electronic signatures (SES), not qualified electronic signatures (QES).';
  }

  function tsaHost(url) {
    try { return new URL(url).host; } catch (e) { return str(url).replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split('/')[0]; }
  }
  /** 'AB:CD:…' — how PDF readers and certificate viewers show a SHA-256 fingerprint. */
  function fingerprint(hex) { return str(hex).replace(/[^0-9a-f]/gi, '').toUpperCase().replace(/(..)(?!$)/g, '$1:'); }

  /** The completed PDF's digital seal: one line, and the certificate behind it on request. */
  function sealStatus(env) {
    var seal = env.status === 'completed' && env.final ? env.final.seal : null;
    if (!seal || typeof seal !== 'object') return null;           // completed before sealing existed: nothing to say
    if (!seal.sealed) {
      return h('div', { class: 'es-seal' }, h('div', { class: 'es-seal-h' }, icon('info'),
        h('span', null, h('span', { class: 'es-seal-t', text: 'Not sealed' }), seal.reason ? ': ' + seal.reason : '')));
    }
    var stamped = seal.level === 'PAdES-B-T';
    var head = stamped
      ? h('span', null, h('span', { class: 'es-seal-t', text: 'Sealed · PAdES · timestamped ' + fmtDateTime(seal.sealed_at) }),
        seal.tsa ? h('span', { class: 'es-dimtxt', text: ' by ' + tsaHost(seal.tsa) }) : null)
      : h('span', null, h('span', { class: 'es-seal-t', text: 'Sealed' }), h('span', { class: 'es-dimtxt', text: ' (no timestamp — the time-stamping service was unavailable)' }));
    var rows = [
      ['Seal certificate', seal.cert_subject],
      ['SHA-256 fingerprint', seal.cert_sha256 ? fingerprint(seal.cert_sha256) : null, true],
      ['Level', seal.level ? seal.level + (stamped ? ' — sealed with an RFC 3161 timestamp' : ' — sealed without a timestamp') : null],
      ['Sealed', seal.sealed_at ? fmtFull(seal.sealed_at) : null],
      ['Time-stamping service', stamped ? seal.tsa : null],
      ['Certificate serial', seal.cert_serial, true]
    ].filter(function (x) { return x[1]; });
    var dl = h('dl', { class: 'es-seal-dl' });
    rows.forEach(function (x) { dl.appendChild(h('dt', { text: x[0] })); dl.appendChild(h('dd', { class: x[2] ? 'es-mono es-break' : null, text: x[1] })); });
    var tip = [seal.cert_subject, seal.cert_sha256 ? 'SHA-256 ' + fingerprint(seal.cert_sha256) : ''].filter(Boolean).join('\n');
    return h('div', { class: 'es-seal es-seal-' + (stamped ? 'ok' : 'warn') },
      h('div', { class: 'es-seal-h', title: tip || null }, icon('shield'), head),
      rows.length ? h('details', { class: 'es-seal-d' }, h('summary', null, icon('next'), h('span', { text: 'Seal certificate' })), dl) : null);
  }

  function routingTimeline(env, recips) {
    var orders = [];
    recips.forEach(function (r) { var o = r.routing_order || 1; if (orders.indexOf(o) < 0) orders.push(o); });
    orders.sort(function (a, b) { return a - b; });
    var ol = h('ol', { class: 'es-route' });
    orders.forEach(function (o, i) {
      var grp = recips.filter(function (r) { return (r.routing_order || 1) === o; });
      var actors = grp.filter(function (r) { return r.role !== 'cc'; });
      var declined = grp.some(function (r) { return r.status === 'declined'; });
      var done = env.status === 'completed' || (actors.length > 0 && actors.every(function (r) { return r.status === 'signed' || r.status === 'completed'; }));
      var current = env.status === 'sent' && env.current_order === o;
      var state = declined ? 'bad' : done ? 'done' : current ? 'cur' : 'todo';
      var node = h('span', { class: 'es-route-n', 'aria-hidden': 'true' }, state === 'done' ? icon('check') : state === 'bad' ? icon('x') : String(i + 1));
      var names = h('ul', { class: 'es-route-r' }, grp.map(function (r) {
        return h('li', { style: { '--es-c': colorOf(r.color) } }, h('span', { class: 'es-r-dot', 'aria-hidden': 'true' }),
          h('span', { class: 'es-ell', text: rName(r) }), h('span', { class: 'es-route-s es-t-' + rcpTone(r, env), text: rcpLabel(r, env) }));
      }));
      ol.appendChild(h('li', { class: 'es-route-g es-rs-' + state, 'aria-current': current ? 'step' : null },
        node, h('div', { class: 'es-route-b' }, h('div', { class: 'es-route-t', text: (orders.length > 1 ? 'Step ' + (i + 1) : 'Everyone at once') + (current ? ' · in progress' : state === 'done' ? ' · done' : state === 'bad' ? ' · declined' : '') }), names)));
    });
    if (!orders.length) ol.appendChild(h('li', { class: 'es-dimtxt', text: 'No recipients.' }));
    return ol;
  }

  function recipientCard(env, r) {
    var inProgress = env.status === 'sent';
    var finished = r.status === 'signed' || r.status === 'declined' || r.status === 'completed';
    var card = h('article', { class: 'es-card es-rcard', style: { '--es-c': colorOf(r.color) }, 'aria-label': rName(r) });
    card.appendChild(h('div', { class: 'es-rcard-h' },
      h('span', { class: 'es-r-dot es-r-dot-l', 'aria-hidden': 'true' }),
      h('div', { class: 'es-grow es-rcard-id' }, h('div', { class: 'es-rcard-n', text: rName(r) }),
        h('div', { class: 'es-hint es-ell' }, str(r.email), ' · ', ROLE_LABEL[r.role] || str(r.role), ' · order\u00a0', String(r.routing_order || 1),   // 'order N' never splits when the line wraps
          // the tags wrap as a group after a plain space, so a wrapped line starts flush instead of indented
          r.access_code_set || r.email_code ? [' ', h('span', { class: 'es-tags' },
            r.access_code_set ? h('span', { class: 'es-tag', title: 'An access code is required to open the link' }, icon('lock'), 'code') : null,
            r.email_code ? h('span', { class: 'es-tag', title: 'A one-time code is emailed to them before they can open the link' }, icon('mail'), 'email code') : null)] : null)),
      rcpChip(r, env)));

    // stepper
    var finalStep = r.role === 'cc'
      ? { label: 'Copy available', at: r.completed_at, done: r.status === 'completed' }
      : r.status === 'declined' ? { label: 'Declined', at: r.declined_at, done: true, bad: true }
        : { label: r.role === 'viewer' ? 'Reviewed' : 'Signed', at: r.signed_at, done: r.status === 'signed' || !!r.signed_at };
    var steps = [
      { label: 'Link generated', at: r.sent_at, done: !!(r.sent_at || r.link) },
      r.link_emailed_at ? { label: 'Emailed', at: r.link_emailed_at, done: true } : { label: 'Shared', at: r.notified_at, done: !!r.notified_at },
      { label: 'Viewed' + (r.view_count > 1 ? ' (' + r.view_count + '×)' : ''), at: r.first_viewed_at, done: !!r.first_viewed_at || (r.view_count > 0) },
      finalStep
    ];
    var st = h('ol', { class: 'es-tl' });
    steps.forEach(function (s) {
      st.appendChild(h('li', { class: 'es-tl-i' + (s.done ? ' es-done' : '') + (s.bad ? ' es-bad' : ''), title: s.at ? fmtFull(s.at) : null },
        h('span', { class: 'es-tl-d', 'aria-hidden': 'true' }, s.done ? icon(s.bad ? 'x' : 'check') : null),
        h('span', { class: 'es-tl-l', text: s.label }),
        h('span', { class: 'es-tl-t', text: s.at ? relTime(s.at) : (s.done ? '✓' : '—') }),
        h('span', { class: 'es-vh', text: s.done ? (s.at ? ' at ' + fmtFull(s.at) : ' done') : ' not yet' })));
    });
    card.appendChild(st);
    if (r.last_viewed_at && r.view_count > 1) card.appendChild(h('div', { class: 'es-hint', text: 'Last viewed ' + relTime(r.last_viewed_at) }));

    if (r.status === 'declined' && r.decline_reason) {
      card.appendChild(callout('red', 'note', 'Reason for declining', '“' + r.decline_reason + '”'));
    }
    if (r.note) card.appendChild(h('div', { class: 'es-rnote' }, icon('note'), h('span', null, h('span', { class: 'es-dimtxt', text: 'Private note: ' }), r.note)));
    if (r.email_verified_at) card.appendChild(h('div', { class: 'es-hint', text: 'Email confirmed ' + fmtFull(r.email_verified_at) + ' with a one-time code' }));
    if (mailOn(env)) {
      if (r.email_state === 'failed' && (r.email_failed_kind === 'completed' || r.email_failed_kind === 'voided' || linkUnshared(env, r))) {
        var whatFailed = r.email_failed_kind === 'completed' ? 'The signed copy' : r.email_failed_kind === 'voided' ? 'The void notice' : 'The link';
        card.appendChild(callout('red', 'mail', 'Email not delivered', whatFailed + ' couldn’t be emailed to ' + str(r.email) + (r.email_error ? ': ' + r.email_error : '') + '.' +
          (env.status === 'completed' && r.email_failed_kind === 'completed' ? ' Download the signed PDF above and send it to them yourself.' : '')));
      }
      else if (r.email_state === 'queued' && r.email_error) card.appendChild(h('div', { class: 'es-hint es-warn-t', text: 'The email didn’t go through yet (' + r.email_error + '). ' + B() + ' tries again later.' }));
      else if (r.email_state === 'queued' && cfg().email_links) card.appendChild(h('div', { class: 'es-hint', text: 'Sending email…' }));
      else if (r.emailed_at && r.email_count > 1) card.appendChild(h('div', { class: 'es-hint', title: fmtFull(r.emailed_at), text: plural(r.email_count, 'email') + ' sent · last ' + relTime(r.emailed_at) }));
    }
    if (r.status === 'signed' && (r.sign_ip || r.signed_at)) {
      card.appendChild(h('div', { class: 'es-hint' }, (r.role === 'viewer' ? 'Reviewed ' : 'Signed ') + fmtFull(r.signed_at) + (r.sign_ip ? ' from IP ' + r.sign_ip : '')));
    }

    var showLink = !!r.link && ((r.role === 'cc' && env.status !== 'voided' && env.status !== 'draft') || (inProgress && !finished));
    if (showLink) card.appendChild(linkBox(env, r));
    else if (inProgress && !r.link && !finished) card.appendChild(h('p', { class: 'es-hint', text: 'No link yet.' }));

    if (inProgress && !finished) {
      var ca = h('div', { class: 'es-rcard-a' });
      ca.appendChild(fk(btn('Correct details', { icon: 'edit', size: 's', kind: 'quiet', onClick: function () { correctDialog(env, r); } }), 'cor-' + r.id));
      card.appendChild(ca);
    }
    return card;
  }

  function mailtoHref(env, r, url) {
    var sender = str(env.sender_name).trim();
    var title = env.title || DEFAULT_TITLE;
    var verb = r.role === 'signer' ? 'review and sign' : r.role === 'viewer' ? 'review' : 'receive a copy of';
    var lines = ['Hi ' + firstName(r.name) + ',', '',
      (sender ? sender + ' has' : 'I have') + ' sent you “' + title + '” to ' + verb + '.'];
    if (str(env.message).trim()) lines.push('', str(env.message).trim());
    lines.push('', 'Open it here (this link is personal to you — please don’t forward it):', url);
    if (r.access_code_set) lines.push('', 'You’ll need an access code to open it — I’ll share it with you separately.');
    if (r.email_code) lines.push('', 'You’ll ' + (r.access_code_set ? 'also ' : '') + 'get a one-time code by email when you open it.');
    if (r.status === 'pending') lines.push('', 'It becomes available to you once the earlier signers have finished.');
    lines.push('', 'Thank you' + (sender ? ',' : ''), sender);
    var subject = (r.role === 'signer' ? 'Please sign: ' : r.role === 'viewer' ? 'Please review: ' : 'For your records: ') + title;
    return 'mailto:' + encodeURIComponent(str(r.email).trim()).replace(/%40/g, '@') +
      '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(lines.join('\r\n').trim());
  }

  function linkBox(env, r) {
    var url = location.origin + r.link;
    var pending = r.status === 'pending';
    var box = h('div', { class: 'es-link' + (pending ? ' es-link-wait' : '') });
    var inp = h('input', { class: 'es-in es-link-in', type: 'text', readonly: true, value: url, 'aria-label': (r.role === 'cc' ? 'View-only link for ' : 'Signing link for ') + rName(r), spellcheck: 'false' });
    inp.readOnly = true;
    inp.addEventListener('focus', function () { inp.select(); });
    fk(inp, 'li-' + r.id);
    box.appendChild(h('div', { class: 'es-link-h' }, icon('link'), h('span', { class: 'es-lbl', text: r.role === 'cc' ? 'View-only link' : 'Signing link' }),
      pending ? h('span', { class: 'es-hint', text: ' · available when it’s their turn' }) : null));
    box.appendChild(inp);
    var acts = h('div', { class: 'es-link-a' });
    var mailed = mailOn(env);
    // envelopes we email: a ready link that isn't on its way by email (it failed, or the link was re-issued
    // without emailing it) is shared by hand, like before
    var mailFailed = mailed && linkUnshared(env, r);
    var canMark = !r.notified_at && env.status === 'sent' && (!mailed || mailFailed);
    function markShared(b) {
      setBusy(b, true);
      return EP.notified(env.id, r.id).then(function (nr) {
        toast('Marked ' + rName(r) + '’s link as shared.', 'ok');
        if (nr && nr.id) replaceRecipient(nr); else refreshDetail(true);
      }, function (err) { setBusy(b, false); toast('Couldn’t mark as shared: ' + errMsg(err), 'err'); });
    }
    var canRemind = mailLive(env) && env.status === 'sent' && r.role !== 'cc' && (r.status === 'sent' || r.status === 'notified' || r.status === 'viewed');
    if (canRemind) {
      // the server's REMIND_GAP applies once the current link has reached them (not after a failure or a new link)
      var lastMail = r.link_emailed_at && r.email_state !== 'failed' ? parseDate(r.emailed_at) : null;
      var soon = lastMail ? lastMail.getTime() + REMIND_GAP_MS : 0;
      var tooSoon = soon > Date.now();
      acts.appendChild(fk(btn(r.email_state === 'failed' ? 'Email again' : r.link_emailed_at ? 'Send reminder' : 'Email link', { icon: 'mail', size: 's', kind: mailFailed ? 'primary' : null,
        disabled: (r.email_state === 'queued' && !r.email_error) || tooSoon,
        title: tooSoon ? 'You can remind them from ' + new Date(soon).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : null,
        onClick: function (e, b) { remindRecipient(env, r, b); } }), 'rm-' + r.id));
    }
    acts.appendChild(fk(btn('Copy link', { icon: 'copy', size: 's', kind: pending || (mailed && !mailFailed) ? null : 'primary', onClick: function () {
      copyText(url, inp).then(function () {
        toast('Link for ' + rName(r) + ' copied.', 'ok', canMark ? { action: { label: 'Mark as shared', fn: function () { markShared(null); } } } : null);
      }, function () {
        inp.focus(); inp.select();
        toast('Couldn’t copy automatically — the link is selected, press Ctrl+C (⌘C on Mac).', 'warn');
      });
    } }), 'cp-' + r.id));
    if (!mailed || mailFailed) {                  /* we email the links: no need for your own mail app */
      var mail = h('a', { class: 'es-btn es-btn-s', href: mailtoHref(env, r, url), title: 'Open a pre-filled email in your mail app' }, icon('mail'), h('span', { class: 'es-btn-t', text: 'Email from my mail app' }));
      fk(mail, 'ml-' + r.id);
      if (canMark) {
        mail.addEventListener('click', function () {
          setTimeout(function () { toast('Sent it? Mark ' + rName(r) + '’s link as shared to keep tracking accurate.', 'info', { action: { label: 'Mark as shared', fn: function () { markShared(null); } } }); }, 600);
        });
      }
      acts.appendChild(mail);
    }
    if (canMark) {
      acts.appendChild(fk(btn('Mark as shared', { icon: 'check', size: 's', onClick: function (e, b) { markShared(b); } }), 'ms-' + r.id));
    } else if (r.link_emailed_at && r.notified_at) {
      acts.appendChild(h('span', { class: 'es-shared', title: fmtFull(r.emailed_at || r.link_emailed_at) }, icon('check'), 'Emailed ' + relTime(r.emailed_at || r.link_emailed_at)));
    } else if (r.notified_at) {
      acts.appendChild(h('span', { class: 'es-shared', title: fmtFull(r.notified_at) }, icon('check'), 'Shared ' + relTime(r.notified_at)));
    }
    if (env.status === 'sent') {
      acts.appendChild(fk(btn('Regenerate link', { icon: 'refresh', size: 's', kind: 'quiet', onClick: function (e, b) { regenerateLink(env, r, b); } }), 'rg-' + r.id));
    }
    box.appendChild(acts);
    if (pending) box.appendChild(h('p', { class: 'es-hint', text: mailLive(env) ? B() + ' emails it to them when it’s their turn. You can also share it now — until earlier signers finish, it shows a “not your turn yet” page.'
      : 'You can share it now — until earlier signers finish, it shows a “not your turn yet” page.' }));
    return box;
  }

  function remindRecipient(env, r, b) {
    setBusy(b, true);
    EP.remind(env.id, r.id).then(function (nr) {
      if (nr && nr.email_state === 'failed') toast('Couldn’t email ' + rName(r) + (nr.email_error ? ': ' + nr.email_error : '') + '. Copy the link and send it yourself.', 'err');
      else if (nr && nr.email_state === 'queued' && nr.email_error) toast('The email to ' + rName(r) + ' didn’t go through yet (' + nr.email_error + ') — ' + B() + ' tries again later.', 'warn');
      else if (nr && nr.email_state === 'queued') toast('Emailing ' + rName(r) + '…', 'ok');
      else if (nr && nr.email_state === 'sent') toast((r.link_emailed_at ? 'Reminder emailed to ' : 'Link emailed to ') + rName(r) + '.', 'ok');
      else toast('The email to ' + rName(r) + ' wasn’t sent — copy the link and send it yourself.', 'warn');
      if (nr && nr.id) replaceRecipient(nr); else refreshDetail(true);
    }, function (err) { setBusy(b, false); toast(errMsg(err), err.status === 429 ? 'warn' : 'err'); });
  }

  function regenerateLink(env, r, b) {
    var emails = mailLive(env) && (r.status === 'sent' || r.status === 'notified' || r.status === 'viewed');
    confirmDialog('Generate a new link for ' + rName(r) + '?\n\nThe current link stops working immediately. ' +
      (emails ? B() + ' emails the new link to ' + str(r.email) + '.' : mailLive(env) && r.status === 'pending' ? B() + ' emails the new link to them when it’s their turn.' : 'You’ll need to share the new link with them.'),
      { title: 'Regenerate link', okLabel: 'Regenerate link', danger: true }).then(function (ok) {
      if (!ok) return;
      setBusy(b, true);
      EP.regenerate(env.id, r.id).then(function (nr) {
        if (nr && nr.id) {
          replaceRecipient(nr);
          if (emails && nr.link_emailed_at && nr.email_state === 'sent') {
            toast('New link emailed to ' + rName(nr) + '. The old one no longer works.', 'ok');
          } else if (emails && nr.email_state === 'queued' && !nr.email_note) {
            toast('New link created — it’s being emailed to ' + rName(nr) + '. The old one no longer works.', 'ok');
          } else if (nr.link) {
            var url = location.origin + nr.link;
            toast('New link created for ' + rName(nr) + '. The old one no longer works.' + (nr.email_note ? ' It wasn’t emailed (' + nr.email_note + ') — share it yourself.' : nr.email_state === 'failed' ? ' It couldn’t be emailed — share it yourself.' : ''), 'ok', { action: { label: 'Copy new link', fn: function () {
              copyText(url, null).then(function () { toast('New link copied.', 'ok'); }, function () { toast('Couldn’t copy — use the Copy link button.', 'warn'); });
            } } });
          }
        } else refreshDetail(true);
      }, function (err) { setBusy(b, false); toast('Couldn’t regenerate: ' + errMsg(err), 'err'); });
    });
  }

  function correctDialog(env, r) {
    var nameIn = h('input', { class: 'es-in', type: 'text', maxlength: '120', value: r.name || '' });
    var emailIn = h('input', { class: 'es-in', type: 'email', maxlength: '200', value: r.email || '' });
    var codeIn = h('input', { class: 'es-in', type: 'password', maxlength: '64', autocomplete: 'new-password', placeholder: r.access_code_set ? '•••••• (set) — leave blank to keep' : 'No code' });
    var show = btn('Show code', { icon: 'eye', iconOnly: true, kind: 'quiet', size: 's', aria: { 'aria-pressed': 'false' }, onClick: function () {
      var s = codeIn.type === 'password';
      codeIn.type = s ? 'text' : 'password';
      show.setAttribute('aria-pressed', s ? 'true' : 'false');
      show.replaceChild(icon(s ? 'eyeoff' : 'eye'), show.firstChild);
    } });
    var rmId = uid('rmc');
    var rmCode = h('input', { type: 'checkbox', id: rmId, class: 'es-cbx' });
    rmCode.addEventListener('change', function () { codeIn.disabled = rmCode.checked; if (rmCode.checked) codeIn.value = ''; });
    var noteIn = h('textarea', { class: 'es-in es-ta', rows: '3', maxlength: '1000', value: r.note || '' });
    var nErr = h('div', { class: 'es-err' }), eErr = h('div', { class: 'es-err' }), formErr = h('div', { class: 'es-err', role: 'alert' });
    var codeField = field('Access code', h('div', { class: 'es-pw' }, codeIn, show), 'Leave blank to keep the current setting.');
    codeIn.id = codeIn.id || uid('cc');
    codeField.querySelector('label').setAttribute('for', codeIn.id);
    var ecSt = emailCodeState(!!r.email_code);
    var ecIn = h('input', { type: 'checkbox', id: uid('ecc'), class: 'es-cbx', checked: !!r.email_code, disabled: ecSt.disabled });
    var ecHint = h('div', { class: 'es-hint' + (ecSt.warn ? ' es-warn-t' : ''), id: uid('ecch'), text: ecSt.hint || ecHintText() });
    ecIn.setAttribute('aria-describedby', ecHint.id);
    var body = [
      h('p', { class: 'es-modal-p', text: 'Fix a typo or update ' + rName(r) + '’s details. The change is recorded in the audit trail. ' +
        'If you change the name or email, they get a new link (the old one stops working).' }),
      field('Name', nameIn, null, nErr), field('Email', emailIn, null, eErr), codeField,
      r.access_code_set ? h('label', { class: 'es-check', for: rmId }, rmCode, h('span', { text: 'Remove the access code' })) : null,
      h('div', { class: 'es-fieldset es-ec' }, h('label', { class: 'es-check', for: ecIn.id }, ecIn, h('span', { text: 'Email them a one-time code' })), ecHint),
      field('Private note', noteIn), formErr
    ];
    modal({ title: 'Correct recipient details', body: body, dismissable: false,
      actions: [{ label: 'Cancel', kind: 'ghost', value: null }, { label: 'Save changes', kind: 'primary', onClick: function () {
        var rr = { name: nameIn.value, email: emailIn.value };
        var errs = rowErrors(rr);
        nErr.textContent = errs.name || ''; eErr.textContent = errs.email || ''; formErr.textContent = '';
        if (errs.name) { nameIn.setAttribute('aria-invalid', 'true'); nameIn.focus(); return false; }
        nameIn.removeAttribute('aria-invalid');
        if (errs.email) { emailIn.setAttribute('aria-invalid', 'true'); emailIn.focus(); return false; }
        emailIn.removeAttribute('aria-invalid');
        var body2 = {};
        if (nameIn.value.trim() !== str(r.name)) body2.name = nameIn.value.trim();
        if (emailIn.value.trim() !== str(r.email)) body2.email = emailIn.value.trim();
        if (rmCode.checked) body2.access_code = '';
        else if (codeIn.value) body2.access_code = codeIn.value;
        if (ecIn.checked !== !!r.email_code) body2.email_code = ecIn.checked;
        if (noteIn.value.trim() !== str(r.note).trim()) body2.note = noteIn.value.trim();
        if (!Object.keys(body2).length) return null;
        return EP.correct(env.id, r.id, body2).then(function (nr) {
          var relinked = (body2.name || body2.email) && mailOn(env) && nr && nr.status !== 'pending';    // email_note says why not, when it wasn't
          var st = relinked ? (nr.email_note ? 'skip' : nr.email_state) : null;
          toast('Details updated for ' + (body2.name || rName(r)) + '.' + (st === 'sent' ? ' A new link was emailed to ' + str(nr.email) + '.'
            : st === 'queued' ? ' A new link is being emailed to ' + str(nr.email) + '.'
              : st === 'failed' ? ' The new link couldn’t be emailed to ' + str(nr.email) + (nr.email_error ? ' (' + nr.email_error + ')' : '') + ' — copy it and send it yourself.'
                : st === 'skip' ? ' The new link wasn’t emailed (' + nr.email_note + ') — copy it and send it yourself.' : ''), st === 'failed' ? 'warn' : 'ok');
          if (nr && nr.id) replaceRecipient(nr); else refreshDetail(true);
          return true;
        }, function (err) { formErr.textContent = errMsg(err); return false; });
      } }] });
  }

  function auditSection(env, byId) {
    var sec = h('section', { class: 'es-audit' });
    var integ = env.integrity;
    var badge;
    if (integ && integ.ok) badge = h('span', { class: 'es-integ es-integ-ok' }, icon('shield'), 'Hash chain verified' + (integ.count ? ' · ' + plural(integ.count, 'event') : ''));
    else if (integ && integ.ok === false) badge = h('span', { class: 'es-integ es-integ-bad', role: 'alert' }, icon('shieldx'), 'Integrity check failed' + (integ.broken_at != null ? ' at event #' + integ.broken_at : ''));
    else badge = h('span', { class: 'es-integ' }, icon('shield'), 'Integrity not reported');
    sec.appendChild(h('div', { class: 'es-audit-h' }, h('h3', { class: 'es-h3', text: 'Audit trail' }), badge));
    var events = arr(env.events).slice().sort(function (a, b) { return (a.seq || 0) - (b.seq || 0); });
    if (!events.length) { sec.appendChild(h('p', { class: 'es-dimtxt', text: 'No events recorded yet.' })); return sec; }
    var tbl = h('table', { class: 'es-tbl' },
      h('caption', { class: 'es-vh', text: 'Audit trail events, oldest first' }),
      h('thead', null, h('tr', null, h('th', { scope: 'col', text: '#' }), h('th', { scope: 'col', text: 'Time' }), h('th', { scope: 'col', text: 'Event' }),
        h('th', { scope: 'col', text: 'By' }), h('th', { scope: 'col', text: 'IP address' }))));
    var tb = h('tbody');
    events.forEach(function (ev) {
      var who = ev.recipient_id && byId[ev.recipient_id] ? rName(byId[ev.recipient_id]) : '';
      var actor = str(ev.actor);
      var by = who && actor && lc(actor) !== lc(who) && actor.indexOf('rcp_') !== 0 ? who + ' (' + actor + ')' : (who || actor || '—');
      var det = detailSummary(ev.detail);
      tb.appendChild(h('tr', { class: /failed|declined|voided|expired|rejected/.test(ev.event || '') ? 'es-tr-warn' : null },
        h('td', { class: 'es-mono es-dimtxt', text: ev.seq != null ? String(ev.seq) : '' }),
        h('td', { class: 'es-nowrap', title: str(ev.ts), text: fmtFull(ev.ts) }),
        h('td', null, h('div', { text: eventLabel(ev) }), det ? h('div', { class: 'es-hint', text: det }) : null),
        h('td', { text: by }),
        h('td', { class: 'es-mono', text: ev.ip || '—', title: ev.ua || null })));
    });
    tbl.appendChild(tb);
    sec.appendChild(h('div', { class: 'es-tbl-wrap', tabindex: '0', role: 'region', 'aria-label': 'Audit trail' }, tbl));
    return sec;
  }
  function humanize(s) { s = str(s).replace(/_/g, ' '); return s.charAt(0).toUpperCase() + s.slice(1); }
  function eventLabel(ev) {
    var note = ev.detail && typeof ev.detail === 'object' ? str(ev.detail.note) : '';
    if (ev.event === 'email_code_failed' && /not sent/i.test(note)) return 'Email code not sent';
    if (ev.event === 'sealed' && !/\bsealed\b/i.test(note)) return 'Final PDF recorded';   // no seal certificate, or sealing failed
    return EVENT_LABEL[ev.event] || humanize(ev.event);
  }
  function detailSummary(d) {
    if (!d || typeof d !== 'object') return d ? String(d).slice(0, 160) : '';
    var parts = [];
    var keys = Object.keys(d);
    if (keys.indexOf('note') > 0) keys = ['note'].concat(keys.filter(function (k) { return k !== 'note'; }));   // the plain sentence first
    keys.slice(0, 6).forEach(function (k) {
      var v = d[k];
      if (v == null || v === '' || /hash|nonce|token|secret|code/i.test(k)) return;
      if (typeof v === 'object') { try { v = Array.isArray(v) ? v.length + ' item' + (v.length === 1 ? '' : 's') : JSON.stringify(v); } catch (e) { v = '…'; } }
      parts.push(humanize(k) + ': ' + String(v));
    });
    var s = parts.join(' · ');
    return s.length > 180 ? s.slice(0, 177) + '…' : s;
  }

  /* ================================================================== VERIFY */
  function goVerify() {
    S.prep = null; S.det = null;
    route('verify');
    setTitle('E-Sign · Verify a document');
    setView('verify', renderVerify);
  }
  function renderVerify(el) {
    var wrap = h('div', { class: 'es-page es-verify' });
    wrap.appendChild(h('div', { class: 'es-topbar' }, backOut()));
    wrap.appendChild(h('div', { class: 'es-pane-head es-center' }, h('div', { class: 'es-kicker', text: B() }), h('h2', { class: 'es-h1', text: 'Verify a document' }),
      h('p', { class: 'es-sub', text: 'Drop a PDF to check whether it is an unmodified original or signed document from one of your envelopes, and whether its digital seal is intact. The fingerprint check compares SHA-256 hashes — changing even one byte breaks the match.' })));
    var input = h('input', { type: 'file', accept: '.pdf,application/pdf', class: 'es-vh', tabindex: '-1', 'aria-hidden': 'true' });
    var choose = btn('Choose a PDF', { icon: 'upload', kind: 'primary', onClick: function () { input.click(); } });
    var zone = h('div', { class: 'es-drop es-drop-v' }, h('div', { class: 'es-drop-ic' }, icon('shield')), h('div', { class: 'es-drop-t', text: 'Drop a PDF here' }),
      h('div', { class: 'es-drop-s', text: 'or' }), choose, input);
    var result = h('div', { class: 'es-vres', 'aria-live': 'polite' });
    input.addEventListener('change', function () { if (input.files && input.files[0]) run(input.files[0]); input.value = ''; });
    var depth = 0;
    zone.addEventListener('dragenter', function (e) { e.preventDefault(); depth++; zone.classList.add('es-over'); });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); e.stopPropagation(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'; });
    zone.addEventListener('dragleave', function () { depth = Math.max(0, depth - 1); if (!depth) zone.classList.remove('es-over'); });
    zone.addEventListener('drop', function (e) {
      e.preventDefault(); e.stopPropagation(); depth = 0; zone.classList.remove('es-over');
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) run(f);
    });
    // the root certificate exists only where a seal is set up (else /root.crt is a 404)
    var rootEl = h('div', { class: 'es-vroot' });
    function fillRoot() {
      rootEl.textContent = '';
      if (!cfg().seal.configured) return;
      rootEl.appendChild(h('div', { class: 'es-note' }, icon('download'),
        h('p', null, h('a', { class: 'es-linkbtn', href: EP.rootCertUrl, download: 'E-Sign-Root-CA.crt' }, 'Download the ' + B() + ' root certificate'),
          ' — import it in your PDF reader to see ' + B() + ' seals as trusted.')));
    }
    S.onCfg = fillRoot;
    fillRoot();
    wrap.appendChild(h('div', { class: 'es-narrow' }, zone, result, rootEl));
    el.appendChild(wrap);

    function run(file) {
      result.textContent = '';
      if (!/\.pdf$/i.test(file.name || '') && file.type !== 'application/pdf') { toast('Please choose a PDF file.', 'err'); return; }
      if (file.size > MAX_FILE * 4) { toast('That file is too large to verify here.', 'err'); return; }
      var nav = S.nav;
      result.appendChild(spinner('Checking “' + file.name + '”…'));
      setBusy(choose, true);
      var hashP = sha256Hex(file);
      EP.verify(file).then(function (res) {
        return hashP.then(function (hx) { return [res, hx]; });
      }).then(function (pair) {
        if (nav !== S.nav) return;
        setBusy(choose, false);
        var res = pair[0] || {}, hx = pair[1];
        result.textContent = '';
        var fp = hx ? h('div', { class: 'es-hint es-mono es-break', text: 'SHA-256 ' + hx }) : null;
        var again = btn('Verify another', { onClick: function () { result.textContent = ''; choose.focus(); } });
        var match;
        if (res.match) {
          var kind = res.kind === 'final' ? 'the final signed document' : res.kind === 'original' ? 'an original uploaded document' : res.kind === 'certificate' ? 'the sealed Certificate of Completion' : 'a document';
          match = h('div', { class: 'es-vsec es-vok' }, h('div', { class: 'es-vic' }, icon('shield')),
            h('div', { class: 'es-grow' }, h('div', { class: 'es-lbl', text: 'Fingerprint' }), h('div', { class: 'es-vt', text: 'Match found' }),
              h('p', null, '“' + file.name + '” is ' + kind + ' of the envelope ', h('strong', { text: '“' + (res.title || res.envelope_id || 'Untitled') + '”' }), '.'),
              res.kind === 'original' ? h('p', { class: 'es-hint', text: 'It matches the file as it was uploaded — before anyone signed it.' }) :
                res.kind === 'final' ? h('p', { class: 'es-hint', text: 'It matches the completed, signed PDF exactly — it hasn’t been altered since signing.' }) :
                  res.kind === 'certificate' ? h('p', { class: 'es-hint', text: 'It matches the standalone Certificate of Completion issued for this envelope.' }) : null,
              fp));
        } else {
          match = h('div', { class: 'es-vsec es-vno' }, h('div', { class: 'es-vic' }, icon('shieldx')),
            h('div', { class: 'es-grow' }, h('div', { class: 'es-lbl', text: 'Fingerprint' }), h('div', { class: 'es-vt', text: 'No match' }),
              h('p', { text: '“' + file.name + '” doesn’t match any original or signed document in your envelopes. It may come from someone else’s account, or it may have been modified (even re-saving a PDF changes its fingerprint).' }),
              fp));
        }
        result.appendChild(h('div', { class: 'es-card es-vcard' }, match, sealSection(res.seal),
          h('div', { class: 'es-row-gap es-vacts' },
            res.match && res.envelope_id ? btn('Open envelope', { kind: 'primary', onClick: function () { openEnvelope(String(res.envelope_id)); } }) : null,
            again)));
      }, function (err) {
        if (nav !== S.nav) return;
        setBusy(choose, false);
        result.textContent = '';
        result.appendChild(callout('red', 'alert', 'Couldn’t verify the file', errMsg(err)));
      });
    }
  }

  /** The seal half of a Verify result. seal: null (no digital signature at all) | {sealed:false} (signatures, but no
   *  the server seal) | {sealed, unchanged, trusted, verdict, signer, timestamp, signed_at}. */
  function sealSection(seal) {
    var v = sealVerdict(seal);
    return h('div', { class: 'es-vsec es-vseal es-v' + v.tone }, h('div', { class: 'es-vic' }, icon(v.ic)),
      h('div', { class: 'es-grow' }, h('div', { class: 'es-lbl', text: 'Digital seal' }), h('div', { class: 'es-vt', text: v.t }),
        v.s ? h('p', { text: v.s }) : null,
        (v.hints || []).filter(Boolean).map(function (x) { return h('p', { class: 'es-hint', text: x }); })));
  }
  function sealVerdict(seal) {
    if (!seal || typeof seal !== 'object') {
      return { tone: 'mute', ic: 'info', t: 'No digital seal in this file', s: 'Only the fingerprint check applies to it.' };
    }
    if (!seal.sealed) {
      var n = arr(seal.signatures).length;
      return { tone: 'mute', ic: 'info', t: 'No ' + B() + ' seal in this file',
        s: n ? 'It carries ' + plural(n, 'other digital signature') + ', but no ' + B() + ' seal. Only the fingerprint check applies to it.' : 'Only the fingerprint check applies to it.' };
    }
    var who = seal.signer ? 'Seal certificate: ' + seal.signer : '';
    var ts = sealTimeLine(seal);
    if (str(seal.verdict).indexOf('seal broken') === 0) {
      return { tone: 'bad', ic: 'shieldx', t: 'Seal broken',
        s: 'The sealed content was altered after sealing, so this copy can’t be relied on. The signed PDF in the envelope is the sealed version.' };
    }
    if (!seal.trusted) {
      // not the the server seal certificate (or not under this server's root): never read it as an the server document
      return { tone: 'bad', ic: 'shieldx', t: 'We can’t confirm who made this seal',
        s: 'This file carries a seal in the ' + B() + ' seal field, but it wasn’t made with this server’s seal certificate. Treat it as unverified.',
        hints: [seal.claimed_signer ? 'The seal names itself “' + seal.claimed_signer + '” — that name is claimed, not confirmed.' : '', untrustedTime(seal)] };
    }
    // the server words verdicts with its brand name ("sealed by <name> and unchanged since"): match on the meaning
    var vd = str(seal.verdict).replace(/^sealed by .+? (and unchanged since)$/, 'sealed $1').replace(/^sealed by .+?, (but the file was changed after sealing)$/, 'sealed, $1');
    switch (vd) {
      case 'sealed and unchanged since':
        return { tone: 'ok', ic: 'shield', t: 'Sealed by ' + B() + ', unchanged since', s: ts,
          hints: [who, seal.trusted_at_timestamp ? 'The seal certificate has since expired; it was valid when the timestamp was made.' : ''] };
      case 'sealed, but the file was changed after sealing':
        return { tone: 'no', ic: 'alert', t: 'Changed after sealing',
          s: 'The sealed content is intact, but something was added to the file after it was sealed — an annotation, a form entry or another signature, for example. The signed PDF in the envelope is the sealed version.', hints: [ts, who] };
      case 'seal broken: the sealed content was altered':
        return { tone: 'bad', ic: 'shieldx', t: 'Seal broken',
          s: 'The sealed content was altered after sealing, so this copy can’t be relied on. The signed PDF in the envelope is the sealed version.', hints: [who] };
      default:
        return { tone: seal.unchanged ? 'ok' : 'no', ic: seal.unchanged ? 'shield' : 'alert',
          t: humanize(seal.verdict) || 'Sealed', s: ts, hints: [who] };
    }
  }
  function sealTimeLine(seal, what) {
    var t = seal.timestamp;
    if (t && t.at && t.intact && t.valid) {
      return 'Timestamped ' + fmtFull(t.at) + (t.trusted ? ' by a trusted time-stamping service.' : ' by a time-stamping service this server doesn’t trust.');
    }
    if (t && t.at) return 'Its timestamp (' + fmtFull(t.at) + ') couldn’t be verified.';
    return 'No timestamp' + (seal.signed_at ? ' — the ' + (what || 'sealing') + ' time, ' + fmtFull(seal.signed_at) + ', comes from this server’s own clock.' : '.');
  }
  function untrustedTime(seal) {
    var t = seal.timestamp;
    if (t && t.at && t.intact && t.valid && t.trusted) return 'A trusted time-stamping service dated it ' + fmtFull(t.at) + '.';
    return 'Its time can’t be confirmed.';
  }

  function sha256Hex(file) {
    try {
      if (!(window.crypto && window.crypto.subtle && file.arrayBuffer)) return Promise.resolve(null);
      return file.arrayBuffer().then(function (buf) { return window.crypto.subtle.digest('SHA-256', buf); }).then(function (d) {
        return Array.prototype.map.call(new Uint8Array(d), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
      }).then(null, function () { return null; });
    } catch (e) { return Promise.resolve(null); }
  }

  /* ================================================================== export */
  /* save everything pending and confirm if something couldn't be saved; resolves true when it's safe to leave */
  function leave() {
    var P = S.prep;
    if (S.view === 'prepare' && P) return leavePrepare(P);
    return Promise.resolve(true);
  }
  window.ESign = { goManage: function () { if (S.mounted) navigate(goManage); }, goVerify: function () { if (S.mounted) navigate(goVerify); }, mount: mount, unmount: unmount, isDirty: isDirty, leave: leave, _esc: esc };
})();
