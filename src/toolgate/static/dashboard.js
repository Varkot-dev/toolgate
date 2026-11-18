// toolgate dashboard. No third-party code, no inline script (the page's CSP forbids it).
// Every HTML fragment inserted here was built and escaped by the server.
"use strict";

(function () {
  const POLL_MS = 2000;
  const JSON_HEADERS = { "Content-Type": "application/json" };

  function $(id) {
    return document.getElementById(id);
  }

  function toLogin() {
    window.location.assign("/dashboard/login");
  }

  // ------------------------------------------------------------------ login
  const loginForm = $("login");
  if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const error = $("login-error");
      error.textContent = "";
      const response = await fetch("/dashboard/login", {
        method: "POST",
        headers: JSON_HEADERS,
        credentials: "same-origin",
        body: JSON.stringify({ key: $("key").value, approver: $("approver").value.trim() }),
      });
      $("key").value = "";
      if (response.ok) {
        window.location.assign("/dashboard");
      } else if (response.status === 401) {
        error.textContent = "That is not the admin key.";
      } else if (response.status === 422) {
        error.textContent = "Enter a name of 1 to 256 printable characters.";
      } else {
        error.textContent = "Sign-in failed (" + response.status + ").";
      }
    });
    return;
  }

  // -------------------------------------------------------------- dashboard
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) return;
  const csrf = meta.getAttribute("content");

  async function getFragment(path) {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store" });
    if (response.status === 401) {
      toLogin();
      throw new Error("signed out");
    }
    return { ok: response.ok, html: await response.text() };
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { ...JSON_HEADERS, "X-CSRF-Token": csrf },
      body: JSON.stringify(body),
    });
    if (response.status === 401) {
      toLogin();
      throw new Error("signed out");
    }
    return { ok: response.ok, html: await response.text() };
  }

  async function refresh(id, path) {
    const result = await getFragment(path);
    const target = $(id);
    if (target.innerHTML !== result.html) target.innerHTML = result.html;
  }

  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    try {
      await Promise.all([
        refresh("feed", "/dashboard/fragment/feed"),
        refresh("queue", "/dashboard/fragment/approvals"),
        refresh("chain", "/dashboard/fragment/chain"),
      ]);
      $("live").classList.remove("stale");
    } catch (err) {
      $("live").classList.add("stale");
    } finally {
      polling = false;
    }
  }

  // Approve and reject: one click each, the server records the session's approver.
  $("queue").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-decision]");
    if (!button) return;
    const card = button.closest(".approval");
    card.querySelectorAll("button").forEach((b) => (b.disabled = true));
    const id = button.getAttribute("data-id");
    const decision = button.getAttribute("data-decision");
    const result = await post("/dashboard/approvals/" + encodeURIComponent(id), { decision });
    $("queue-notice").innerHTML = result.html;
    await poll();
  });

  // Clicking a block picks it for the tamper demo.
  function pick(event) {
    const block = event.target.closest(".block[data-seq]");
    if (block) $("tamper-seq").value = block.getAttribute("data-seq");
  }
  $("chain").addEventListener("click", pick);

  $("verify").addEventListener("click", async () => {
    const result = await getFragment("/dashboard/fragment/verify");
    $("verify-result").innerHTML = result.html;
  });

  $("tamper").addEventListener("submit", async (event) => {
    event.preventDefault();
    const seq = Number.parseInt($("tamper-seq").value, 10);
    const field = $("tamper-field").value;
    const result = await post("/dashboard/tamper", { seq, field });
    const target = $("tamper-result");
    target.innerHTML = result.html;
    // The demo shows the real log itself, so the live chain view steps aside.
    $("tamper").closest(".panel").classList.toggle("demo-open", result.ok);
    target.scrollIntoView({ block: "nearest" });
  });

  $("tamper-result").addEventListener("click", (event) => {
    if (event.target.closest("#close-demo")) {
      $("tamper-result").innerHTML = "";
      $("tamper").closest(".panel").classList.remove("demo-open");
      return;
    }
    pick(event);
  });

  $("logout").addEventListener("click", async () => {
    try {
      await post("/dashboard/logout", {});
    } finally {
      toLogin();
    }
  });

  poll();
  window.setInterval(poll, POLL_MS);
})();
