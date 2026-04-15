(function () {
  "use strict";

  const API = "api/index.php";

  function apiUrl(action) {
    return API + "?action=" + encodeURIComponent(action);
  }

  function apiUrlWithQuery(action, params) {
    let u = API + "?action=" + encodeURIComponent(action);
    const keys = Object.keys(params || {});
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      u += "&" + encodeURIComponent(k) + "=" + encodeURIComponent(String(params[k]));
    }
    return u;
  }

  function showAlert(el, message, type) {
    if (!el) return;
    el.textContent = message;
    el.className = "alert visible " + (type || "error");
  }

  function showSuccess(el, message) {
    showAlert(el, message, "success");
  }

  function hideAlert(el) {
    if (!el) return;
    el.className = "alert";
    el.textContent = "";
  }

  /** Forgot page: copy reset URL (global for optional onclick). */
  function copyResetLink() {
    const input = document.getElementById("resetLinkInput");
    if (!input) return;
    const value = input.value;
    const done = function () {
      window.alert("Copied!");
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done).catch(function () {
        input.focus();
        input.select();
        input.setSelectionRange(0, value.length);
        try {
          document.execCommand("copy");
          done();
        } catch (err2) {
          window.alert("Could not copy automatically. Select the link and press Ctrl+C.");
        }
      });
      return;
    }
    input.focus();
    input.select();
    input.setSelectionRange(0, value.length);
    try {
      document.execCommand("copy");
      done();
    } catch (err) {
      window.alert("Could not copy automatically. Select the link and press Ctrl+C.");
    }
  }
  window.copyResetLink = copyResetLink;

  function renderForgotResetLink(resultBox, url) {
    resultBox.innerHTML = "";
    const box = document.createElement("div");
    box.className = "success-box";

    const p = document.createElement("p");
    p.textContent = "Reset link generated:";
    box.appendChild(p);

    const input = document.createElement("input");
    input.type = "text";
    input.id = "resetLinkInput";
    input.readOnly = true;
    input.setAttribute("aria-label", "Password reset link");
    input.value = url;
    box.appendChild(input);

    const actions = document.createElement("div");
    actions.className = "reset-link-actions";

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-ghost btn-sm btn-copy";
    copyBtn.textContent = "Copy";
    copyBtn.addEventListener("click", copyResetLink);
    actions.appendChild(copyBtn);

    const openLink = document.createElement("a");
    openLink.href = url;
    openLink.target = "_blank";
    openLink.rel = "noopener noreferrer";
    openLink.className = "reset-link-open";
    openLink.textContent = "Open reset page";
    actions.appendChild(openLink);

    box.appendChild(actions);
    resultBox.appendChild(box);
  }

  function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).trim());
  }

  function validatePassword(pw) {
    return String(pw).length >= 6;
  }

  function validateName(name) {
    const n = String(name).trim();
    return n.length > 0 && n.length <= 120;
  }

  async function postJson(action, body) {
    const res = await fetch(apiUrl(action), {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    const data = parseJsonResponse(res, text);
    return { ok: res.ok, status: res.status, data: data };
  }

  function parseJsonResponse(res, text) {
    try {
      return text ? JSON.parse(text) : {};
    } catch (err) {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("[smart-auth] Non-JSON response (" + res.status + "):", String(text).slice(0, 400));
      }
      return {
        success: false,
        message: "Invalid server response. Check the Network tab for HTML or PHP errors.",
      };
    }
  }

  async function getJson(action) {
    const res = await fetch(apiUrl(action), {
      method: "GET",
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    const text = await res.text();
    const data = parseJsonResponse(res, text);
    return { ok: res.ok, status: res.status, data: data };
  }

  async function getJsonQuery(action, queryParams) {
    const res = await fetch(apiUrlWithQuery(action, queryParams), {
      method: "GET",
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    const text = await res.text();
    const data = parseJsonResponse(res, text);
    return { ok: res.ok, status: res.status, data: data };
  }

  function bindLogout(btn) {
    if (!btn) return;
    btn.addEventListener("click", async function () {
      btn.disabled = true;
      const result = await postJson("logout", {});
      btn.disabled = false;
      if (result.ok && result.data.success) {
        window.location.href = result.data.redirect || "index.html";
        return;
      }
      window.location.href = "index.html";
    });
  }

  /** SVG icons for password visibility (single control per field — no stacked toggles). */
  var PASSWORD_TOGGLE_SVG_SHOW =
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>' +
    '<circle cx="12" cy="12" r="3"/>' +
    "</svg>";
  var PASSWORD_TOGGLE_SVG_HIDE =
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>' +
    '<line x1="1" y1="1" x2="23" y2="23"/>' +
    "</svg>";

  /**
   * Show/hide password for every `.password-field` (login, register, reset).
   * Expects: input + one `.toggle-password` (button) with `.toggle-password__icon` inside.
   */
  function initPasswordToggles() {
    document.querySelectorAll(".password-field").forEach(function (wrap) {
      const input = wrap.querySelector("input");
      const btn = wrap.querySelector(".toggle-password");
      const icon = btn ? btn.querySelector(".toggle-password__icon") : null;
      if (!input || !btn || !icon || btn.dataset.toggleBound === "1") {
        return;
      }
      btn.dataset.toggleBound = "1";

      function syncUi() {
        const revealed = input.type === "text";
        icon.innerHTML = revealed ? PASSWORD_TOGGLE_SVG_HIDE : PASSWORD_TOGGLE_SVG_SHOW;
        btn.setAttribute("aria-pressed", revealed ? "true" : "false");
        btn.setAttribute("aria-label", revealed ? "Hide password" : "Show password");
        btn.title = revealed ? "Hide password" : "Show password";
      }

      btn.addEventListener("click", function (e) {
        e.preventDefault();
        input.type = input.type === "password" ? "text" : "password";
        syncUi();
      });

      syncUi();
    });
  }

  initPasswordToggles();

  /* Login page: discourage autofill and clear fields after Chrome may inject saved values */
  (function initLoginAutofillGuard() {
    const form = document.getElementById("login-form");
    if (!form) {
      return;
    }
    function clearLoginInputs() {
      form.querySelectorAll("input").forEach(function (input) {
        if (input.type === "checkbox") {
          input.checked = false;
          return;
        }
        input.value = "";
      });
    }
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", clearLoginInputs);
    } else {
      clearLoginInputs();
    }
    setTimeout(clearLoginInputs, 50);
    setTimeout(clearLoginInputs, 200);
  })();

  /* Login */
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    const alertEl = document.getElementById("form-alert");
    loginForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      hideAlert(alertEl);
      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;
      const remember = document.getElementById("remember").checked;

      if (!validateEmail(email)) {
        showAlert(alertEl, "Please enter a valid email address.", "error");
        return;
      }
      if (!password) {
        showAlert(alertEl, "Password is required.", "error");
        return;
      }

      const btn = loginForm.querySelector('button[type="submit"]');
      btn.disabled = true;
      const result = await postJson("login", { email: email, password: password, remember: remember });
      btn.disabled = false;

      if (result.ok && result.data.success) {
        showAlert(alertEl, result.data.message || "Success.", "success");
        const role = result.data.role || (result.data.user && result.data.user.role) || "user";
        const redir = role === "admin" ? "admin.html" : "dashboard.html";
        setTimeout(function () {
          window.location.href = redir;
        }, 400);
        return;
      }
      showAlert(alertEl, result.data.message || "Login failed.", "error");
    });
  }

  /* Register */
  const registerForm = document.getElementById("register-form");
  if (registerForm) {
    const alertEl = document.getElementById("form-alert");
    registerForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      hideAlert(alertEl);
      const name = document.getElementById("name").value;
      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;

      if (!validateName(name)) {
        showAlert(alertEl, "Please enter your name (max 120 characters).", "error");
        return;
      }
      if (!validateEmail(email)) {
        showAlert(alertEl, "Please enter a valid email address.", "error");
        return;
      }
      if (!validatePassword(password)) {
        showAlert(alertEl, "Password must be at least 6 characters.", "error");
        return;
      }

      const btn = registerForm.querySelector('button[type="submit"]');
      btn.disabled = true;
      const result = await postJson("register", {
        name: name.trim(),
        email: email.trim(),
        password: password,
      });
      btn.disabled = false;

      if (result.ok && result.data.success) {
        showAlert(alertEl, result.data.message || "Registered.", "success");
        const redir = result.data.redirect || "index.html";
        setTimeout(function () {
          window.location.href = redir;
        }, 1200);
        return;
      }
      showAlert(alertEl, result.data.message || "Registration failed.", "error");
    });
  }

  /* Verify email */
  if (document.getElementById("page-verify")) {
    const alertEl = document.getElementById("form-alert");
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const title = document.querySelector(".card h2");
    if (!token) {
      if (title) title.textContent = "Verification failed";
      showAlert(alertEl, "Missing verification token.", "error");
    } else {
      getJsonQuery("verify_email", { token: token }).then(function (result) {
        if (title) title.textContent = result.ok && result.data.success ? "Verified" : "Verification failed";
        if (result.ok && result.data.success) {
          showAlert(alertEl, result.data.message || "Your email is verified.", "success");
        } else {
          showAlert(alertEl, result.data.message || "Verification failed.", "error");
        }
      });
    }
  }

  /* Forgot password */
  const forgotForm = document.getElementById("forgot-form");
  if (forgotForm) {
    const alertEl = document.getElementById("form-alert");
    const resultBox = document.getElementById("resultBox");
    forgotForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      hideAlert(alertEl);
      if (resultBox) {
        resultBox.innerHTML = "";
      }
      const email = document.getElementById("email").value;
      if (!validateEmail(email)) {
        showAlert(alertEl, "Please enter a valid email address.", "error");
        return;
      }
      const btn = forgotForm.querySelector('button[type="submit"]');
      btn.disabled = true;
      const result = await postJson("forgot_password", { email: email.trim() });
      btn.disabled = false;
      const data = result.data;
      if (result.ok && data.success) {
        if (data.reset_link && resultBox) {
          showSuccess(alertEl, "Reset link generated");
          renderForgotResetLink(resultBox, data.reset_link);
          if (typeof console !== "undefined" && console.log) {
            console.log("Reset link:", data.reset_link);
          }
        } else {
          showAlert(
            alertEl,
            "No account uses that email. Register first at register.html, or fix typos—then request a reset again.",
            "error"
          );
        }
        return;
      }
      showAlert(alertEl, (data && data.message) || "Request failed.", "error");
    });
  }

  /* Reset password */
  const resetForm = document.getElementById("reset-form");
  if (resetForm) {
    const alertEl = document.getElementById("form-alert");
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const tokenInput = document.getElementById("token");
    if (tokenInput) tokenInput.value = (token || "").trim();
    if (!token) {
      showAlert(alertEl, "Missing reset token. Use the link from your email.", "error");
    }
    resetForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      hideAlert(alertEl);
      const pw = document.getElementById("password").value;
      const t = (tokenInput ? tokenInput.value : "").trim();
      if (!t) {
        showAlert(alertEl, "Missing reset token.", "error");
        return;
      }
      if (!validatePassword(pw)) {
        showAlert(alertEl, "Password must be at least 6 characters.", "error");
        return;
      }
      const btn = resetForm.querySelector('button[type="submit"]');
      btn.disabled = true;
      const result = await postJson("reset_password", { token: t, password: pw });
      btn.disabled = false;
      if (result.ok && result.data.success) {
        showAlert(alertEl, result.data.message || "Password updated.", "success");
        setTimeout(function () {
          window.location.href = result.data.redirect || "index.html";
        }, 800);
        return;
      }
      showAlert(alertEl, result.data.message || "Reset failed.", "error");
    });
  }

  /* Dashboard */
  const dash = document.getElementById("dashboard");
  if (dash) {
    const alertEl = document.getElementById("form-alert");
    const userName = document.getElementById("user-name");
    const userEmail = document.getElementById("user-email");
    const userCreated = document.getElementById("user-created");
    const userRole = document.getElementById("user-role");
    const userVerified = document.getElementById("user-verified");
    const logoutBtn = document.getElementById("logout-btn");
    const logoutNav = document.getElementById("logout-btn-nav");
    const navAdmin = document.getElementById("nav-admin");

    getJson("me").then(function (result) {
      if (!result.ok || !result.data.success || !result.data.user) {
        showAlert(alertEl, "Please sign in to view this page.", "error");
        setTimeout(function () {
          window.location.href = "index.html";
        }, 1200);
        return;
      }
      hideAlert(alertEl);
      const u = result.data.user;
      if (userName) userName.textContent = u.name;
      if (userEmail) userEmail.textContent = u.email;
      if (userCreated) userCreated.textContent = u.created_at || "—";
      if (userRole) userRole.textContent = u.role || "user";
      if (userVerified) userVerified.textContent = u.is_verified ? "Yes" : "No";
      if (navAdmin && u.role === "admin") {
        navAdmin.style.display = "";
      }
    });

    bindLogout(logoutBtn);
    bindLogout(logoutNav);
  }

  /* Admin */
  const adminPanel = document.getElementById("admin-panel");
  if (adminPanel) {
    const alertEl = document.getElementById("form-alert");
    const tbody = document.getElementById("users-tbody");
    const logoutBtn = document.getElementById("admin-logout");

    function renderUsers(users) {
      if (!tbody) return;
      tbody.innerHTML = "";
      users.forEach(function (u) {
        const tr = document.createElement("tr");
        const roleBadge =
          u.role === "admin"
            ? '<span class="badge badge-admin">admin</span>'
            : '<span class="badge badge-user">user</span>';
        const verBadge = u.is_verified
          ? '<span class="badge badge-yes">Verified</span>'
          : '<span class="badge badge-no">Pending</span>';
        tr.innerHTML =
          "<td>" +
          String(u.id) +
          "</td>" +
          "<td></td>" +
          "<td></td>" +
          "<td>" +
          roleBadge +
          "</td>" +
          "<td>" +
          verBadge +
          "</td>" +
          "<td></td>";
        const cells = tr.querySelectorAll("td");
        cells[1].textContent = u.name;
        cells[2].textContent = u.email;
        const actions = document.createElement("div");
        actions.className = "row-actions";
        const sel = document.createElement("select");
        sel.setAttribute("aria-label", "Role for user " + u.id);
        ["user", "admin"].forEach(function (r) {
          const opt = document.createElement("option");
          opt.value = r;
          opt.textContent = r;
          if (u.role === r) opt.selected = true;
          sel.appendChild(opt);
        });
        sel.addEventListener("change", async function () {
          hideAlert(alertEl);
          const result = await postJson("change_role", { user_id: u.id, role: sel.value });
          if (result.ok && result.data.success) {
            showAlert(alertEl, result.data.message || "Updated.", "success");
            loadUsers();
            return;
          }
          showAlert(alertEl, result.data.message || "Failed.", "error");
          loadUsers();
        });
        const del = document.createElement("button");
        del.type = "button";
        del.className = "btn btn-danger btn-sm";
        del.textContent = "Delete";
        del.addEventListener("click", async function () {
          if (!window.confirm("Delete this user?")) return;
          hideAlert(alertEl);
          const result = await postJson("delete_user", { user_id: u.id });
          if (result.ok && result.data.success) {
            showAlert(alertEl, result.data.message || "Deleted.", "success");
            loadUsers();
            return;
          }
          showAlert(alertEl, result.data.message || "Failed.", "error");
        });
        actions.appendChild(sel);
        actions.appendChild(del);
        cells[5].appendChild(actions);
        tbody.appendChild(tr);
      });
    }

    async function loadUsers() {
      const result = await getJson("admin_users");
      if (!result.ok || !result.data.success || !result.data.users) {
        showAlert(alertEl, result.data.message || "Could not load users.", "error");
        return;
      }
      hideAlert(alertEl);
      renderUsers(result.data.users);
    }

    getJson("me").then(async function (result) {
      if (!result.ok || !result.data.success || !result.data.user) {
        showAlert(alertEl, "Please sign in.", "error");
        setTimeout(function () {
          window.location.href = "index.html";
        }, 1000);
        return;
      }
      if (result.data.user.role !== "admin") {
        showAlert(alertEl, "Access denied.", "error");
        setTimeout(function () {
          window.location.href = "dashboard.html";
        }, 1000);
        return;
      }
      await loadUsers();
    });

    bindLogout(logoutBtn);
  }
})();
