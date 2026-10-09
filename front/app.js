// Browser client for Node SSE E2EE relay
// End-to-End Encryption with ECDH P-256 + AES-GCM 256

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

// Inline reply-arrow icon
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

// Markdown parser with safe sanitization and media embedding
function formatMarkdown(rawText) {
  let s = escapeHtml(rawText);

  // 1. Code blocks ```code```
  s = s.replace(/```([\s\S]*?)```/g, (m, code) => `<pre class="md-pre"><code>${code.trim()}</code></pre>`);

  // 2. Inline code `code`
  s = s.replace(/`([^`\n]+)`/g, '<code class="md-code">$1</code>');

  // 3. Bold **text** or __text__
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/__([^_]+)__/g, '<strong>$1</strong>');

  // 4. Italic *text* or _text_
  s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  s = s.replace(/_([^_]+)_/g, '<em>$1</em>');

  // 5. Strikethrough ~~text~~
  s = s.replace(/~~([^~]+)~~/g, '<del>$1</del>');

  // 6. Blockquotes > quote
  s = s.replace(/^&gt;\s?(.*)$/gm, '<blockquote class="md-quote">$1</blockquote>');

  // 7. Markdown links [text](https://...)
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" class="md-link">$1</a>');

  // 8. Privacy-preserving media embed: Click-to-load prevents IP address leaks to external hosts
  s = s.replace(/(https?:\/\/[^\s<]+?\.(?:gif|png|jpe?g|webp)(?:\?[^\s<]*)?)/gi, (url) => {
    return `<div class="chat-embed-blocked" data-src="${url}">` +
      `<span class="embed-warning">[ Media distant - Cliquer pour charger (expose votre IP à l'hôte) ]</span>` +
      `</div>`;
  });

  // 9. Plain URL auto-linking
  s = s.replace(/(^|[\s(])(https?:\/\/[^\s<]+)/g, (m, pre, url) => {
    if (url.match(/\.(gif|png|jpe?g|webp)/i)) return m;
    return `${pre}<a href="${url}" target="_blank" rel="noopener noreferrer" class="md-link">${url}</a>`;
  });

  // 10. Preserved newlines
  s = s.replace(/\n/g, '<br>');

  return s;
}

class Client {
  constructor() {
    this.room = null;
    this.user = null;
    this.peer = null;
    this.keys = null; // { publicKey, privateKey }
    this.sharedKeys = new Map(); // peerUser -> CryptoKey
    this.peerPubKeys = new Map(); // peerUser -> pubKeyRawB64
    this.peers = new Map(); // username -> { user, pubKeyRawB64, online }
    this.es = null; // EventSource
    this.server = location.origin;

    this.messages = new Map(); // id -> { id, from, text, replyTo }
    this.replyingTo = null; // { id, from, text }
    this.baseTitle = document.title;
    this.unreadCount = 0;

    this.ui = this.bindUI();
    this.setupNotifications();
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
      peersList: document.getElementById('peers-list'),
      peersCount: document.getElementById('peers-count'),
      stickerBtn: document.getElementById('sticker-btn'),
      stickerPanel: document.getElementById('sticker-panel'),
      gifUrlInput: document.getElementById('gif-url-input'),
      gifInsertBtn: document.getElementById('gif-insert-btn'),
    };

    ui.connect.addEventListener('click', () => this.connect());
    ui.send.addEventListener('click', () => this.onSend());

    // Multiline: Enter sends, Shift+Enter adds newline
    ui.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.onSend();
      }
    });

    // Auto-expand textarea
    ui.input.addEventListener('input', () => {
      ui.input.style.height = 'auto';
      ui.input.style.height = Math.min(ui.input.scrollHeight, 140) + 'px';
    });

    ui.replyCancel.addEventListener('click', () => this.cancelReply());

    // Event delegation for reply button and click-to-load media
    ui.log.addEventListener('click', (e) => {
      const blocked = e.target.closest('.chat-embed-blocked');
      if (blocked && blocked.dataset.src) {
        const url = blocked.dataset.src;
        blocked.outerHTML = `<a href="${url}" target="_blank" rel="noopener noreferrer" class="chat-embed-link"><img src="${url}" class="chat-embed-img" loading="lazy" alt="embed" /></a>`;
        return;
      }

      const btn = e.target.closest('.reply-btn');
      if (!btn) return;
      const id = btn.dataset.target;
      this.startReply(id);
    });

    // Sticker and GIF panel toggles
    if (ui.stickerBtn && ui.stickerPanel) {
      ui.stickerBtn.addEventListener('click', () => this.toggleStickerPanel());

      document.querySelectorAll('.sticker-item').forEach((btn) => {
        btn.addEventListener('click', () => {
          const text = btn.dataset.text;
          if (text) {
            this.insertTextAtCursor(text);
            this.toggleStickerPanel();
          }
        });
      });

      if (ui.gifInsertBtn && ui.gifUrlInput) {
        ui.gifInsertBtn.addEventListener('click', () => {
          const url = ui.gifUrlInput.value.trim();
          if (url) {
            this.insertTextAtCursor(url);
            ui.gifUrlInput.value = '';
            this.toggleStickerPanel();
          }
        });
      }
    }

    // Auto-update peer when user edits peer input directly
    ui.peer.addEventListener('input', () => {
      this.peer = ui.peer.value.trim();
      this.renderPeers();
    });

    return ui;
  }

  setupNotifications() {
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) this.clearNotifications();
    });
    window.addEventListener('focus', () => {
      this.clearNotifications();
    });
  }

  notifyUnread() {
    if (document.hidden) {
      this.unreadCount++;
      document.title = `(•) ${this.baseTitle}`;
    }
  }

  clearNotifications() {
    this.unreadCount = 0;
    document.title = this.baseTitle;
  }

  toggleStickerPanel() {
    if (!this.ui.stickerPanel) return;
    const isVisible = this.ui.stickerPanel.style.display !== 'none';
    this.ui.stickerPanel.style.display = isVisible ? 'none' : 'flex';
    if (!isVisible && this.ui.gifUrlInput) {
      this.ui.gifUrlInput.focus();
    }
  }

  insertTextAtCursor(text) {
    const input = this.ui.input;
    const start = input.selectionStart || 0;
    const end = input.selectionEnd || 0;
    const val = input.value;
    input.value = val.slice(0, start) + text + val.slice(end);
    input.selectionStart = input.selectionEnd = start + text.length;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 140) + 'px';
    input.focus();
  }

  setStatus(s) {
    this.ui.status.textContent = s;
  }

  startReply(id) {
    const original = this.messages.get(id);
    if (!original) return;
    this.replyingTo = { id: original.id, from: original.from, text: original.text };
    this.ui.replyPreviewText.innerHTML = `${REPLY_ICON} ${escapeHtml(original.from)} : ${escapeHtml(truncate(original.text, 60))}`;
    this.ui.replyPreview.style.display = 'flex';
    this.ui.input.focus();
  }

  cancelReply() {
    this.replyingTo = null;
    this.ui.replyPreview.style.display = 'none';
  }

  logMsg(msg) {
    this.messages.set(msg.id, msg);

    const el = document.createElement('div');
    el.className = 'msg';
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

    const content = document.createElement('div');
    content.className = 'msg-content';

    const isSystemMessage = msg.from === 'Système' || msg.from === 'Erreur';
    if (!isSystemMessage && msg.from !== this.user) {
      content.classList.add('peer');
    }

    const from = document.createElement('span');
    from.className = 'from';
    from.textContent = `${msg.from}:`;
    content.appendChild(from);

    const textSpan = document.createElement('span');
    if (isSystemMessage) {
      textSpan.textContent = msg.text;
    } else {
      textSpan.innerHTML = formatMarkdown(msg.text);
    }
    content.appendChild(textSpan);

    body.appendChild(content);
    el.appendChild(body);

    if (!isSystemMessage) {
      const btn = document.createElement('button');
      btn.className = 'reply-btn';
      btn.dataset.target = msg.id;
      btn.innerHTML = REPLY_ICON;
      btn.title = 'Répondre';
      el.appendChild(btn);
    }

    this.ui.log.appendChild(el);
    this.ui.log.scrollTop = this.ui.log.scrollHeight;

    if (!isSystemMessage && msg.from !== this.user) {
      this.notifyUnread();
    }
  }

  logSystem(from, text) {
    this.logMsg({ id: newId(), from, text, replyTo: null });
  }

  debug(obj) {
    this.ui.debug.textContent = JSON.stringify(obj, null, 2);
  }

  // Ephemeral in-RAM keypair generation & RAM synchronization across tabs via BroadcastChannel (Zero disk traces)
  async getOrCreateKeys(room, user) {
    // Purge any legacy localStorage traces
    try {
      Object.keys(localStorage).filter((k) => k.startsWith('kr1pt3d_')).forEach((k) => localStorage.removeItem(k));
    } catch (_) {}

    // Check if another tab in this browser session already holds the key in RAM
    if (window.BroadcastChannel) {
      const channelName = `kr1pt3d_ephemeral_${encodeURIComponent(room)}`;
      const bc = new BroadcastChannel(channelName);

      const sharedFromTab = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve(null), 90);
        const onMsg = async (e) => {
          if (e.data && e.data.type === 'response_key' && e.data.user === user) {
            clearTimeout(timer);
            bc.removeEventListener('message', onMsg);
            try {
              const privateKey = await crypto.subtle.importKey(
                'jwk',
                e.data.privateJwk,
                { name: 'ECDH', namedCurve: 'P-256' },
                true,
                ['deriveKey']
              );
              const publicKey = await crypto.subtle.importKey(
                'raw',
                fromB64(e.data.pubB64),
                { name: 'ECDH', namedCurve: 'P-256' },
                true,
                []
              );
              resolve({ keys: { privateKey, publicKey }, pubB64: e.data.pubB64 });
            } catch (_) {
              resolve(null);
            }
          }
        };
        bc.addEventListener('message', onMsg);
        bc.postMessage({ type: 'request_key', user });
      });

      if (sharedFromTab) {
        this.setupKeySharing(bc, user, sharedFromTab.keys, sharedFromTab.pubB64);
        return sharedFromTab;
      }
    }

    // Fresh ephemeral generation in RAM
    const keys = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );
    const pubRaw = await crypto.subtle.exportKey('raw', keys.publicKey);
    const pubB64 = toB64(pubRaw);

    if (window.BroadcastChannel) {
      const channelName = `kr1pt3d_ephemeral_${encodeURIComponent(room)}`;
      const bc = new BroadcastChannel(channelName);
      this.setupKeySharing(bc, user, keys, pubB64);
    }

    return { keys, pubB64 };
  }

  async setupKeySharing(bc, user, keys, pubB64) {
    try {
      const privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
      bc.addEventListener('message', (e) => {
        if (e.data && e.data.type === 'request_key' && e.data.user === user) {
          bc.postMessage({ type: 'response_key', user, pubB64, privateJwk });
        }
      });
    } catch (_) {}
  }

  async connect() {
    try {
      if (!window.isSecureContext) {
        console.warn('Web Crypto recommande HTTPS ou localhost.');
      }
      if (!crypto?.subtle) throw new Error('crypto.subtle non disponible');

      this.room = this.ui.room.value.trim() || 'demo-room';
      this.user = this.ui.user.value.trim();
      this.peer = this.ui.peer.value.trim();

      if (!this.user) throw new Error("Veuillez renseigner un nom d'utilisateur (Username)");

      this.setStatus('Initialisation des clés…');
      const { keys, pubB64 } = await this.getOrCreateKeys(this.room, this.user);
      this.keys = keys;

      await this.openSSE();

      // Register public key
      await fetch(`${this.server}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room: this.room, user: this.user, pubKeyRawB64: pubB64 }),
      });

      // Fetch all peers in the room
      await this.fetchPeers();

      this.setStatus('Connecté');
      this.ui.input.disabled = false;
      this.ui.send.disabled = false;
      if (this.ui.stickerBtn) this.ui.stickerBtn.disabled = false;

      this.logSystem('Système', `Connecté en tant que ${this.user} dans la room "${this.room}".`);
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
      this.onPeerJoined(data.user, data.pubKeyRawB64, data.online);
    });

    this.es.addEventListener('peer-left', (ev) => {
      const data = JSON.parse(ev.data);
      this.onPeerLeft(data.user);
    });

    this.es.addEventListener('message', (ev) => this.onCipherMessage(ev));
    this.es.onerror = (e) => {
      console.warn('SSE error', e);
    };
  }

  async fetchPeers() {
    try {
      const res = await fetch(`${this.server}/peers?room=${encodeURIComponent(this.room)}`);
      const json = await res.json();
      (json.peers || []).forEach((p) => {
        this.peers.set(p.user, p);
        if (p.pubKeyRawB64) {
          this.peerPubKeys.set(p.user, p.pubKeyRawB64);
        }
      });
      this.renderPeers();

      if (this.peer && this.peerPubKeys.has(this.peer)) {
        await this.getSharedKey(this.peer);
      }
    } catch (err) {
      console.warn('Erreur récupération peers:', err);
    }
  }

  onPeerJoined(user, pubKeyRawB64, online = true) {
    const existing = this.peers.get(user);
    const pubKeyChanged = existing && existing.pubKeyRawB64 !== pubKeyRawB64;

    this.peers.set(user, { user, pubKeyRawB64, online });
    if (pubKeyRawB64) {
      this.peerPubKeys.set(user, pubKeyRawB64);
      if (pubKeyChanged) {
        this.sharedKeys.delete(user);
      }
    }
    this.renderPeers();

    if (user === this.peer) {
      this.getSharedKey(user);
    }
  }

  onPeerLeft(user) {
    if (this.peers.has(user)) {
      const peer = this.peers.get(user);
      peer.online = false;
      this.renderPeers();
    }
  }

  renderPeers() {
    if (!this.ui.peersList) return;
    const peerEntries = Array.from(this.peers.values()).filter((p) => p.user !== this.user);
    if (this.ui.peersCount) this.ui.peersCount.textContent = peerEntries.length;

    if (peerEntries.length === 0) {
      this.ui.peersList.innerHTML = '<div class="empty-peers">No peers connected</div>';
      return;
    }

    this.ui.peersList.innerHTML = '';
    peerEntries.forEach((peer) => {
      const item = document.createElement('div');
      item.className = 'peer-item' + (peer.user === this.peer ? ' active' : '');
      item.dataset.user = peer.user;

      const dot = document.createElement('span');
      dot.className = 'peer-dot' + (peer.online ? ' online' : '');

      const name = document.createElement('span');
      name.className = 'peer-name';
      name.textContent = peer.user;

      item.appendChild(dot);
      item.appendChild(name);

      item.addEventListener('click', () => {
        this.selectPeer(peer.user);
      });

      this.ui.peersList.appendChild(item);
    });
  }

  async selectPeer(peerUser) {
    this.peer = peerUser;
    this.ui.peer.value = peerUser;
    this.renderPeers();
    this.logSystem('Système', `Sélection du pair : ${peerUser}.`);
    const key = await this.getSharedKey(peerUser);
    if (key) {
      this.logSystem('Système', `Clé de session prête avec ${peerUser}.`);
    } else {
      this.logSystem('Système', `En attente de la clé publique de ${peerUser}…`);
    }
    this.ui.input.focus();
  }

  async getSharedKey(peerUser) {
    if (!peerUser) return null;
    if (this.sharedKeys.has(peerUser)) {
      return this.sharedKeys.get(peerUser);
    }

    let pubB64 = this.peerPubKeys.get(peerUser);
    if (!pubB64) {
      await this.fetchPeers();
      pubB64 = this.peerPubKeys.get(peerUser);
    }
    if (!pubB64) return null;

    try {
      const peerPubKey = await crypto.subtle.importKey(
        'raw',
        fromB64(pubB64),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      );
      const shared = await crypto.subtle.deriveKey(
        { name: 'ECDH', public: peerPubKey },
        this.keys.privateKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      this.sharedKeys.set(peerUser, shared);
      return shared;
    } catch (err) {
      console.warn(`Erreur dérivation clé pour ${peerUser}:`, err);
      return null;
    }
  }

  async onSend() {
    const text = this.ui.input.value.trim();
    if (!text) return;

    if (!this.peer) {
      this.peer = this.ui.peer.value.trim();
      if (!this.peer) {
        this.logSystem('Système', 'Veuillez renseigner ou sélectionner un correspondant (Peer).');
        return;
      }
    }

    const sharedKey = await this.getSharedKey(this.peer);
    if (!sharedKey) {
      this.logSystem('Système', `En attente de la clé partagée avec ${this.peer}…`);
      return;
    }

    this.ui.input.value = '';
    this.ui.input.style.height = 'auto';

    const id = newId();
    const replyTo = this.replyingTo;
    const plain = JSON.stringify({ id, text, replyTo });

    const iv = randBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, te.encode(plain));
    const payload = { ivB64: toB64(iv), ctB64: toB64(ct) };

    await fetch(`${this.server}/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ room: this.room, from: this.user, to: this.peer, payload }),
    });

    this.logMsg({ id, from: this.user, text, replyTo });
    this.cancelReply();
  }

  async onCipherMessage(ev) {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.to !== this.user) return;

      const sharedKey = await this.getSharedKey(msg.from);
      if (!sharedKey) {
        this.logSystem('Erreur', `Clé introuvable pour déchiffrer le message de ${msg.from}.`);
        return;
      }

      const iv = new Uint8Array(fromB64(msg.payload.ivB64));
      const ct = fromB64(msg.payload.ctB64);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sharedKey, ct);
      const raw = td.decode(pt);

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
      console.warn('Erreur déchiffrement message:', e);
      this.logSystem('Erreur', 'Impossible de déchiffrer un message.');
    }
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new Client();
});