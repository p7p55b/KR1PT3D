// Browser client for C++ SSE E2EE relay

const te = new TextEncoder();
const td = new TextDecoder();

function toB64(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}
function fromB64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function randBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
// Inline reply-arrow icon (currentColor so it follows the button/text color)
const REPLY_ICON = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><polyline points="9 10 4 15 9 20"></polyline><path d="M4 15h11a4 4 0 0 0 0-8h-1"></path></svg>';

function newId() {
  return (crypto.randomUUID) ? crypto.randomUUID() : toB64(randBytes(16));
}
function truncate(s, n) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}
function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = String(s);
  return div.innerHTML;
}

class Client {
  constructor() {
    this.room = null;
    this.user = null;
    this.peer = null;
    this.keys = null; // { publicKey, privateKey }
    this.shared = null; // AES-GCM key
    this.es = null; // EventSource
    this.server = location.origin; // same host

    this.messages = new Map(); // id -> { id, from, text, replyTo }
    this.replyingTo = null; // { id, from, text } of the message currently being replied to

    this.ui = this.bindUI();
  }

  bindUI() {
    const ui = {
      room: document.getElementById('room'),
      user: document.getElementById('user'),
      peer: document.getElementById('peer'),
      connect: document.getElementById('connect'),
      status: document.getElementById('status'),
      debug: document.getElementById('debug'),
      log: document.getElementById('log'),
      input: document.getElementById('input'),
      send: document.getElementById('send'),
      replyPreview: document.getElementById('reply-preview'),
      replyPreviewText: document.getElementById('reply-preview-text'),
      replyCancel: document.getElementById('reply-cancel'),
    };
    ui.connect.addEventListener('click', () => this.connect());
    ui.send.addEventListener('click', () => this.onSend());
    ui.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.onSend();
    });
    ui.replyCancel.addEventListener('click', () => this.cancelReply());

    // Event delegation: click on any "reply" button inside the message log
    ui.log.addEventListener('click', (e) => {
      const btn = e.target.closest('.reply-btn');
      if (!btn) return;
      const id = btn.dataset.target;
      this.startReply(id);
    });

    return ui;
  }

  setStatus(s) { this.ui.status.textContent = s; }

  startReply(id) {
    const original = this.messages.get(id);
    if (!original) return;
    this.replyingTo = { id: original.id, from: original.from, text: original.text };
    this.ui.replyPreviewText.innerHTML = `${REPLY_ICON} ${original.from} : ${escapeHtml(truncate(original.text, 60))}`;
    this.ui.replyPreview.style.display = 'flex';
    this.ui.input.focus();
  }

  cancelReply() {
    this.replyingTo = null;
    this.ui.replyPreview.style.display = 'none';
  }

  // Renders a message bubble. `msg` = { id, from, text, replyTo }
  // replyTo, when present, is a plain { id, from, text } snapshot (not a live lookup),
  // so the quote still displays even if the original scrolled out or came from before reconnect.
  logMsg(msg) {
    this.messages.set(msg.id, msg);

    const el = document.createElement('div');
    el.className = 'msg';
    if (msg.from !== this.user) el.classList.add('peer');
    el.dataset.id = msg.id;

    const body = document.createElement('div');
    body.className = 'msg-body';

    if (msg.replyTo) {
      const quote = document.createElement('div');
      quote.className = 'msg-reply-quote';
      quote.innerHTML = `${REPLY_ICON} ${escapeHtml(msg.replyTo.from)} : ${escapeHtml(truncate(msg.replyTo.text, 60))}`;
      quote.title = 'Aller au message original';
      quote.addEventListener('click', () => {
        const target = this.ui.log.querySelector(`[data-id="${msg.replyTo.id}"]`);
        if (target) target.scrollIntoView({ block: 'center', behavior: 'smooth' });
      });
      body.appendChild(quote);
    }

    const from = document.createElement('span');
    from.className = 'from';
    from.textContent = `${msg.from}:`;
    body.appendChild(from);
    body.appendChild(document.createTextNode(msg.text));

    el.appendChild(body);

    // "Système"/"Erreur" lines have no real id to reply to
    if (msg.from !== 'Système' && msg.from !== 'Erreur') {
      const btn = document.createElement('button');
      btn.className = 'reply-btn';
      btn.dataset.target = msg.id;
      btn.innerHTML = REPLY_ICON;
      btn.title = 'Répondre';
      el.appendChild(btn);
    }

    this.ui.log.appendChild(el);
    this.ui.log.scrollTop = this.ui.log.scrollHeight;
  }

  // Convenience for system/error lines, which don't need an id or reply button
  logSystem(from, text) {
    this.logMsg({ id: newId(), from, text, replyTo: null });
  }

  debug(obj) { this.ui.debug.textContent = JSON.stringify(obj, null, 2); }

  async connect() {
    try {
      if (!window.isSecureContext) {
        console.warn('Web Crypto recommande HTTPS ou localhost.');
      }
      if (!crypto?.subtle) throw new Error('crypto.subtle non disponible');

      this.room = this.ui.room.value.trim() || 'demo-room';
      this.user = this.ui.user.value.trim();
      this.peer = this.ui.peer.value.trim();
      if (!this.user || !this.peer) throw new Error('Renseignez user et peer');

      this.setStatus('Génération des clés…');
      this.keys = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey']
      );
      const pubRaw = await crypto.subtle.exportKey('raw', this.keys.publicKey);
      const pubB64 = toB64(pubRaw);

      await this.openSSE();

      await fetch(`${this.server}/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room: this.room, user: this.user, pubKeyRawB64: pubB64 }),
      });

      await this.tryDeriveWithPeers();

      this.setStatus('Connecté');
      this.ui.input.disabled = false;
      this.ui.send.disabled = false;
      this.logSystem('Système', 'Connecté. En attente/échange de clé avec le pair.');
    } catch (e) {
      console.error(e);
      this.setStatus(`Erreur: ${e.message}`);
    }
  }

  async openSSE() {
    if (this.es) this.es.close();
    const url = `${this.server}/events?room=${encodeURIComponent(this.room)}&user=${encodeURIComponent(this.user)}`;
    this.es = new EventSource(url);
    this.es.addEventListener('peer-joined', (ev) => {
      const data = JSON.parse(ev.data);
      if (data.user === this.peer) {
        this.debug({ peerJoined: data.user });
        this.tryDeriveWithPeers();
      }
    });
    this.es.addEventListener('message', (ev) => this.onCipherMessage(ev));
    this.es.onerror = (e) => { console.warn('SSE error', e); };
  }

  async tryDeriveWithPeers() {
    const res = await fetch(`${this.server}/peers?room=${encodeURIComponent(this.room)}`);
    const json = await res.json();
    const peerEntry = json.peers.find((p) => p.user === this.peer);
    if (!peerEntry) return;
    await this.deriveShared(peerEntry.pubKeyRawB64);
  }
  async deriveShared(peerPubB64) {
    const peerPubKey = await crypto.subtle.importKey('raw', fromB64(peerPubB64), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    this.shared = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPubKey }, this.keys.privateKey,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']
    );
    this.logSystem('Système', `Clé de session établie avec ${this.peer}.`);
  }

  async onSend() {
    const text = this.ui.input.value.trim();
    if (!text) return;
    this.ui.input.value = '';
    if (!this.shared) { this.logSystem('Système','En attente de la clé partagée…'); await this.tryDeriveWithPeers(); if (!this.shared) return; }

    const id = newId();
    const replyTo = this.replyingTo; // { id, from, text } or null

    // The reply metadata travels *inside* the encrypted payload, not alongside it,
    // so the relay server never learns which message is being replied to.
    const plain = JSON.stringify({ id, text, replyTo });

    const iv = randBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.shared, te.encode(plain));
    const payload = { ivB64: toB64(iv), ctB64: toB64(ct) };
    await fetch(`${this.server}/send`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ room:this.room, from:this.user, to:this.peer, payload }) });

    this.logMsg({ id, from: this.user, text, replyTo });
    this.cancelReply();
  }

  async onCipherMessage(ev) {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.to !== this.user) return;
      if (!this.shared) await this.tryDeriveWithPeers();
      const iv = new Uint8Array(fromB64(msg.payload.ivB64));
      const ct = fromB64(msg.payload.ctB64);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.shared, ct);
      const raw = td.decode(pt);

      // Backward-compatible parse: older peers may still send plain text instead of JSON.
      let id, text, replyTo;
      try {
        const parsed = JSON.parse(raw);
        id = parsed.id || newId();
        text = parsed.text;
        replyTo = parsed.replyTo || null;
      } catch {
        id = newId();
        text = raw;
        replyTo = null;
      }

      this.logMsg({ id, from: msg.from, text, replyTo });
    } catch (e) {
      this.logSystem('Erreur', 'Impossible de déchiffrer un message.');
    }
  }
}

window.addEventListener('DOMContentLoaded', () => { new Client(); });