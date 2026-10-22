/* Inbox page: set up the inbox once, then unlock it with the passphrase to
 * read, copy and delete messages. The passphrase, the private key and the
 * decrypted messages only ever exist in this page's memory. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const show = (el, on) => { el.hidden = !on; };
  const say = (el, msg) => { el.textContent = msg || ""; show(el, !!msg); };
  const MIN_PASS = 12;

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

  if (!SM.supported) {
    show($("loading"), false);
    say($("load-error"), "This browser can't decrypt. Please use an up-to-date browser.");
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
    const code = $("setup-code").value.trim().toUpperCase();
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
    session = { token, privateKey, publicKey: inboxInfo.publicKey };
    show($("unlock"), false);
    show($("inbox"), true);
    $("fp").textContent = await SM.fingerprint(inboxInfo.publicKey);
    $("send-link").textContent = location.origin + location.pathname.replace(/inbox\.html$/, "");
    await render(data.messages);
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
    $("messages").replaceChildren();
    show($("inbox"), false);
    show($("unlock"), true);
    $("pass").focus();
  });

  // Lock automatically after 10 minutes in the background.
  let hiddenAt = 0;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { hiddenAt = Date.now(); return; }
    if (session && hiddenAt && Date.now() - hiddenAt > 10 * 60 * 1000) $("lock").click();
  });

  // ---- messages ----------------------------------------------------------
  const timeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

  async function render(list) {
    const items = await Promise.all(list.map(async (m) => {
      try {
        return { ...m, ...(await SM.openMessage(session.privateKey, session.publicKey, m.blob)) };
      } catch (_) {
        return { ...m, broken: true };
      }
    }));
    const ol = $("messages");
    ol.replaceChildren(...items.map(card));
    updateSummary();
  }

  function updateSummary() {
    const n = $("messages").children.length;
    $("summary").textContent = n === 0 ? "No messages yet." : n === 1 ? "1 message" : `${n} messages`;
  }

  function card(m) {
    const li = $("message-tpl").content.firstElementChild.cloneNode(true);
    const time = li.querySelector("time");
    time.dateTime = m.created_at;
    time.textContent = timeFmt.format(new Date(m.created_at));
    li.querySelector(".from").textContent = m.broken ? "" : m.from ? `From: ${m.from}` : "Anonymous";
    const body = li.querySelector(".plain");
    body.textContent = m.broken ? "This message couldn't be decrypted." : m.text;
    if (m.broken) body.classList.add("broken");

    const copyBtn = li.querySelector(".copy");
    show(copyBtn, !m.broken);
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(m.text);
        copyBtn.textContent = "Copied ✓";
        setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
      } catch (_) { /* clipboard blocked: the text is selectable */ }
    });

    const delBtn = li.querySelector(".delete");
    delBtn.addEventListener("click", async () => {
      if (!confirm("Delete this message for good?")) return;
      const done = busy(delBtn, "Deleting…");
      try {
        await SM.rpc("delete_message", { token: session.token, message_id: m.id });
        li.remove();
        updateSummary();
      } catch (e) {
        done();
        say($("inbox-error"), e.code === "PGRST202"
          ? "Deleting isn't switched on yet for this inbox."
          : friendly(e, "Your session has expired. Lock and unlock again."));
      }
    });
    return li;
  }

  $("refresh").addEventListener("click", async () => {
    const done = busy($("refresh"), "Refreshing…");
    say($("inbox-error"), "");
    try {
      const data = await SM.rpc("open_inbox", { token: session.token });
      await render(data.messages);
    } catch (e) {
      say($("inbox-error"), friendly(e, "Your passphrase was changed. Lock and unlock again."));
    } finally {
      done();
    }
  });

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
