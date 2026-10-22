/* Inbox page: set up the inbox once, then unlock it with the passphrase to
 * read and reply to conversations. The passphrase, the private key and the
 * decrypted messages only ever exist in this page's memory. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const show = (el, on) => { el.hidden = !on; };
  const say = (el, msg) => { el.textContent = msg || ""; show(el, !!msg); };
  const MIN_PASS = 12;

  let notifyReady = false;

  // Set while unlocked.
  let session = null; // { token, privateKey, publicKey }

  function busy(btn, label) {
    const old = btn.textContent;
    btn.disabled = true;
    btn.textContent = label;
    return () => { btn.disabled = false; btn.textContent = old; };
  }

  function friendly(e, wrongMsg) {
    if (e && e.code === "28000") return wrongMsg;
    if (e && e.code === "offline") return e.message;
    return "Something went wrong. Please try again.";
  }

  function checkNewPassphrase(a, b) {
    if (a.length < MIN_PASS) return `Use at least ${MIN_PASS} characters.`;
    if (a !== b) return "The two passphrases don't match.";
    return "";
  }

  if (!window.SM) return; // moving to https://
  SM.applyLogo().then((logo) => { if (logo) $("logo-preview").src = logo; });
  if (!SM.supported) {
    show($("loading"), false);
    say($("load-error"), SM.unsupportedMessage);
    return;
  }

  // ---- start -------------------------------------------------------------
  let inboxInfo = null; // { publicKey, salt }
  (async function start() {
    try {
      inboxInfo = await SM.ownerPublicKey();
    } catch (e) {
      show($("loading"), false);
      say($("load-error"), e.code === "key-mismatch"
        ? "The inbox key doesn't match the key pinned in this site's settings."
        : friendly(e, ""));
      return;
    }
    show($("loading"), false);
    if (!inboxInfo.publicKey) {
      show($("setup"), true);
      $("setup-code").focus();
    } else {
      show($("unlock"), true);
      $("pass").focus();
    }
  })();

  // ---- setup -------------------------------------------------------------
  $("setup-btn").addEventListener("click", async () => {
    // Phones like to turn "-" into "–" or add spaces when pasting, so keep
    // only letters and digits and put the dashes back ourselves.
    const code = ($("setup-code").value.toUpperCase().replace(/[^A-Z0-9]/g, "").match(/.{1,4}/g) || []).join("-");
    const pass = $("setup-pass").value;
    const problem = !code ? "Enter your setup code." : checkNewPassphrase(pass, $("setup-pass2").value);
    if (problem) { say($("setup-error"), problem); return; }
    say($("setup-error"), "");
    const done = busy($("setup-btn"), "Creating keys…");
    try {
      const inbox = await SM.newInbox(pass);
      await SM.rpc("setup_inbox", {
        setup_code: code,
        public_key: inbox.public_key,
        salt: inbox.salt,
        auth_hash: inbox.auth_hash,
        wrapped_key: inbox.wrapped_key,
      });
      inboxInfo = { publicKey: inbox.public_key, salt: inbox.salt };
      $("setup-pass").value = $("setup-pass2").value = "";
      show($("setup"), false);
      await unlockWith(pass);
    } catch (e) {
      say($("setup-error"), friendly(e, "That setup code isn't right, or this inbox is already set up."));
    } finally {
      done();
    }
  });

  // ---- unlock ------------------------------------------------------------
  async function unlockWith(pass) {
    const { token, wrapKey } = await SM.fromPassphrase(pass, inboxInfo.salt);
    const data = await SM.rpc("open_inbox", { token });
    const privateKey = await SM.unwrapPrivateKey(data.wrapped_key, wrapKey);
    session = { token, privateKey, publicKey: inboxInfo.publicKey, keys: new Map(), drafts: new Map() };
    show($("unlock"), false);
    show($("inbox"), true);
    $("fp").textContent = await SM.fingerprint(inboxInfo.publicKey);
    $("send-link").textContent = location.origin + location.pathname.replace(/inbox(\.html)?$/, "");
    if (!notifyReady) {
      notifyReady = true;
      SM.setupNotifyButton($("notify"), $("notify-note"), "sm-notify-owner",
        (sub) => SM.rpc("subscribe_owner", { token: session.token, ...sub }));
    }
    await render(data.threads);
  }

  async function unlock() {
    const pass = $("pass").value;
    if (!pass) { say($("unlock-error"), "Enter your passphrase."); return; }
    say($("unlock-error"), "");
    const done = busy($("unlock-btn"), "Unlocking…");
    try {
      await unlockWith(pass);
      $("pass").value = "";
    } catch (e) {
      say($("unlock-error"), friendly(e, "Wrong passphrase."));
    } finally {
      done();
    }
  }
  $("unlock-btn").addEventListener("click", unlock);
  $("pass").addEventListener("keydown", (e) => { if (e.key === "Enter") unlock(); });

  $("lock").addEventListener("click", () => {
    session = null;
    cards.clear();
    $("threads").replaceChildren();
    show($("inbox"), false);
    show($("unlock"), true);
    $("pass").focus();
  });

  // Lock automatically after 10 minutes in the background; otherwise catch up
  // on new messages as soon as the inbox is back on screen.
  let hiddenAt = 0;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { hiddenAt = Date.now(); return; }
    if (session && hiddenAt && Date.now() - hiddenAt > 10 * 60 * 1000) $("lock").click();
    else poll();
  });

  // New messages appear by themselves: check every few seconds while the
  // inbox is open and on screen.
  const POLL_MS = 3000;
  let polling = false;
  async function poll() {
    if (!session || polling || document.hidden) return;
    polling = true;
    try {
      await refresh();
      setLive(true);
    } catch (_) {
      setLive(false); // try again next time
    }
    polling = false;
  }
  function setLive(ok) {
    const el = $("live");
    el.hidden = false;
    el.classList.toggle("off", !ok);
    el.textContent = ok ? "● Live · new messages appear by themselves" : "○ Reconnecting…";
  }
  setInterval(poll, POLL_MS);

  // ---- conversations ---------------------------------------------------
  // Each conversation's key comes sealed to the owner in its envelope.
  async function threadKey(t) {
    if (!session.keys.has(t.id)) {
      session.keys.set(t.id, SM.openEnvelope(session.privateKey, session.publicKey, t.id, t.envelope));
    }
    return session.keys.get(t.id);
  }

  // Cards already on screen, by thread id, with a signature of what they
  // show; unchanged conversations are reused rather than decrypted again.
  const cards = new Map(); // id -> { sig, node }
  const signature = (t) => {
    const msgs = t.messages || [];
    return `${msgs.length}:${msgs.length ? msgs[msgs.length - 1].id : ""}:${t.last_from_owner}`;
  };

  async function render(threads) {
    const nodes = await Promise.all(threads.map(async (t) => {
      const sig = signature(t);
      const old = cards.get(t.id);
      if (old && old.sig === sig) return old.node;
      let item;
      try {
        const key = await threadKey(t);
        item = { ...t, key, messages: await SM.openAll(key, t.messages) };
      } catch (_) {
        session.keys.delete(t.id);
        item = { ...t, broken: true, messages: [] };
      }
      const node = card(item);
      cards.set(t.id, { sig, node });
      return node;
    }));
    for (const id of [...cards.keys()]) if (!threads.some((t) => t.id === id)) cards.delete(id);

    const list = $("threads");
    if (nodes.length === list.children.length && nodes.every((n, i) => list.children[i] === n)) { updateSummary(); return; }
    // Rebuilding the list moves the reply box you're typing in; put the
    // cursor back where it was.
    const active = document.activeElement;
    const focusId = active && list.contains(active) ? active.id : "";
    const sel = focusId && active.tagName === "TEXTAREA" ? [active.selectionStart, active.selectionEnd] : null;
    list.replaceChildren(...nodes);
    if (focusId) {
      const el = document.getElementById(focusId);
      if (el) {
        el.focus({ preventScroll: true });
        if (sel) el.setSelectionRange(sel[0], sel[1]);
      }
    }
    updateSummary();
  }

  function updateSummary() {
    const cards = [...$("threads").children];
    const n = cards.length;
    const waiting = cards.filter((c) => c.classList.contains("unanswered")).length;
    $("summary").textContent = n === 0 ? "No messages yet."
      : (n === 1 ? "1 conversation" : `${n} conversations`) + (waiting ? ` · ${waiting} waiting for a reply` : "");
  }

  function bubble(m) {
    const li = $("bubble-tpl").content.firstElementChild.cloneNode(true);
    li.classList.add(m.from_owner ? "mine" : "theirs");
    const body = li.querySelector(".plain");
    body.textContent = m.broken ? "This message couldn't be decrypted." : m.text;
    if (m.broken) body.classList.add("broken");
    const time = li.querySelector("time");
    time.dateTime = m.created_at;
    time.textContent = (m.from_owner ? "You · " : "") + SM.formatTime(m.created_at);
    return li;
  }

  function card(t) {
    const li = $("thread-tpl").content.firstElementChild.cloneNode(true);
    if (!t.last_from_owner) li.classList.add("unanswered");
    const named = t.messages.find((m) => !m.from_owner && m.from);
    li.querySelector(".from").textContent = t.broken ? "Unreadable conversation" : named ? named.from : "Complaint";
    li.querySelector(".badge").hidden = t.last_from_owner;
    const time = li.querySelector("time");
    time.dateTime = t.last_at;
    time.textContent = SM.formatTime(t.last_at);
    li.querySelector(".thread").replaceChildren(...t.messages.map(bubble));

    const box = li.querySelector("textarea");
    const replyBtn = li.querySelector(".reply");
    const err = li.querySelector(".error");
    box.id = "reply-" + t.id.slice(0, 12);
    li.querySelector("label").htmlFor = box.id;
    box.value = session.drafts.get(t.id) || "";
    box.addEventListener("input", () => session.drafts.set(t.id, box.value));
    show(box.closest(".reply-box"), !t.broken);

    replyBtn.addEventListener("click", async () => {
      const text = box.value;
      if (!text.trim()) { say(err, "Write a reply first."); return; }
      say(err, "");
      const done = busy(replyBtn, "Sending…");
      try {
        const blob = await SM.sealMessage(t.key, true, text);
        await SM.rpc("reply_to_thread", { token: session.token, thread_id: t.id, blob });
        session.drafts.delete(t.id);
        await refresh();
      } catch (e) {
        done();
        say(err, e.message === "too long" ? "That reply is too long. Please shorten it."
          : friendly(e, "Your session has expired. Lock and unlock again."));
      }
    });

    const delBtn = li.querySelector(".delete");
    delBtn.addEventListener("click", async () => {
      if (!confirm("Delete this whole conversation for good? The other person won't be able to see it either.")) return;
      const done = busy(delBtn, "Deleting…");
      try {
        await SM.rpc("delete_thread", { token: session.token, thread_id: t.id });
        cards.delete(t.id);
        li.remove();
        updateSummary();
      } catch (e) {
        done();
        say(err, e.code === "PGRST202"
          ? "Deleting isn't switched on yet for this inbox."
          : friendly(e, "Your session has expired. Lock and unlock again."));
      }
    });
    return li;
  }

  async function refresh() {
    const data = await SM.rpc("open_inbox", { token: session.token });
    await render(data.threads);
  }

  $("refresh").addEventListener("click", async () => {
    const done = busy($("refresh"), "Refreshing…");
    say($("inbox-error"), "");
    try {
      await refresh();
    } catch (e) {
      say($("inbox-error"), friendly(e, "Your passphrase was changed. Lock and unlock again."));
    } finally {
      done();
    }
  });

  // ---- logo --------------------------------------------------------------
  let pendingLogo = null;
  $("logo-file").addEventListener("change", async () => {
    say($("logo-msg"), "");
    pendingLogo = null;
    $("logo-save").disabled = true;
    try {
      pendingLogo = await SM.logoFromFile($("logo-file").files[0]);
      $("logo-preview").src = pendingLogo;
      $("logo-save").disabled = false;
    } catch (_) {
      say($("logo-msg"), "That file isn't a picture this browser can open. Try a PNG or JPEG.");
    }
  });

  async function saveLogo(logo, btn, doneMsg) {
    const done = busy(btn, "Saving…");
    try {
      await SM.rpc("set_logo", { token: session.token, logo });
      document.querySelectorAll(".brand img").forEach((img) => { img.src = logo || "favicon.svg"; });
      $("logo-preview").src = logo || "favicon.svg";
      say($("logo-msg"), doneMsg);
      pendingLogo = null;
      $("logo-file").value = "";
    } catch (e) {
      say($("logo-msg"), friendly(e, "Your session has expired. Lock and unlock again."));
    } finally {
      done();
      $("logo-save").disabled = !pendingLogo;
    }
  }
  $("logo-save").addEventListener("click", () => {
    if (pendingLogo) saveLogo(pendingLogo, $("logo-save"), "Logo saved. It now shows on every page.");
  });
  $("logo-reset").addEventListener("click", () => saveLogo(null, $("logo-reset"), "Back to the default logo."));

  // ---- change passphrase -------------------------------------------------
  $("change-btn").addEventListener("click", async () => {
    const pass = $("new-pass").value;
    const problem = checkNewPassphrase(pass, $("new-pass2").value);
    say($("change-msg"), "");
    if (problem) { say($("change-error"), problem); return; }
    say($("change-error"), "");
    const done = busy($("change-btn"), "Changing…");
    try {
      const creds = await SM.newCredentials(pass, session.privateKey);
      await SM.rpc("change_passphrase", {
        token: session.token, salt: creds.salt, auth_hash: creds.auth_hash, wrapped_key: creds.wrapped_key,
      });
      session.token = creds.token;
      inboxInfo.salt = creds.salt;
      $("new-pass").value = $("new-pass2").value = "";
      say($("change-msg"), "Passphrase changed. Use the new one from now on.");
    } catch (e) {
      say($("change-error"), friendly(e, "Your session has expired. Lock and unlock again."));
    } finally {
      done();
    }
  });
})();
