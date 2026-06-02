"""Server-rendered /login page.

No React, no JavaScript dependency. Listed providers come from the
registry; clicking a provider sends a GET to
``/auth/login?provider=<name>``.

Visual styling mirrors the Nous Research design system (the
``@nous-research/ui`` package the React dashboard uses): the same
``Collapse`` / ``Rules Compressed`` typeface, amber-on-dark colour
tokens (``#170d02`` / ``#ffac02`` / ``#fff``), uppercase + wide-tracking
brand chrome, and the inset-bevel button shadow. Fonts are served
out of the SPA's ``/fonts/`` directory which the dashboard-auth gate
already allowlists pre-auth (see ``_GATE_PUBLIC_PREFIXES`` in
``middleware.py``), so the page renders without needing the React
bundle loaded.

Test-stable class names: the existing test suite extracts the
``class="provider-btn"`` anchor href to walk the OAuth flow. That
class name MUST NOT change without updating
``tests/hermes_cli/test_dashboard_auth_401_reauth.py``.
"""
from __future__ import annotations

import html

from hermes_cli.dashboard_auth import list_providers

# Inline minimal CSS. The dashboard's full skin lives in the React
# bundle, which we deliberately do NOT load here — the login page must
# not depend on the SPA build being present or on the injected session
# token.
#
# Single curly braces are placeholders for ``str.format``; CSS curlies
# are doubled (``{{`` / ``}}``).
_LOGIN_HTML_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Hermes Agent</title>
<style>
  /* Brand fonts shipped by @nous-research/ui — same files the SPA loads. */
  @font-face {{
    font-family: 'Collapse';
    font-style: normal;
    font-weight: 400;
    font-display: swap;
    src: url('/fonts/Collapse-Regular.woff2') format('woff2');
  }}
  @font-face {{
    font-family: 'Collapse';
    font-style: normal;
    font-weight: 700;
    font-display: swap;
    src: url('/fonts/Collapse-Bold.woff2') format('woff2');
  }}
  @font-face {{
    font-family: 'Rules Compressed';
    font-style: normal;
    font-weight: 400;
    font-display: swap;
    src: url('/fonts/RulesCompressed-Regular.woff2') format('woff2');
  }}
  @font-face {{
    font-family: 'Rules Compressed';
    font-style: normal;
    font-weight: 600;
    font-display: swap;
    src: url('/fonts/RulesCompressed-Medium.woff2') format('woff2');
  }}

  :root {{
    --background-base: #170d02;
    --background: #170d02;
    --midground: #ffac02;
    --foreground: #ffffff;
    --hairline: color-mix(in srgb, #ffac02 18%, transparent);
    --hairline-strong: color-mix(in srgb, #ffac02 35%, transparent);
  }}

  *, *::before, *::after {{ box-sizing: border-box; }}

  html, body {{
    margin: 0;
    padding: 0;
    min-height: 100%;
    background: var(--background-base);
    color: var(--foreground);
    font-family: 'Collapse', system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    font-size: 16px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }}

  /* Subtle dot-grid backdrop — DS idiom (see `.dither` in globals.css). */
  body {{
    background-image:
      radial-gradient(
        ellipse at top,
        color-mix(in srgb, var(--midground) 6%, transparent) 0%,
        transparent 55%
      ),
      repeating-conic-gradient(
        color-mix(in srgb, var(--midground) 4%, transparent) 0% 25%,
        transparent 0% 50%
      );
    background-size: auto, 3px 3px;
    background-attachment: fixed;
  }}

  /* Layout: vertically center on tall screens, top-anchor on short. */
  body {{
    display: grid;
    place-items: center;
    padding: clamp(1.5rem, 6vh, 6rem) 1.25rem;
  }}

  main {{
    width: 100%;
    max-width: 26rem;
    position: relative;
    animation: slide-up 0.6s ease-out both;
  }}

  @keyframes slide-up {{
    from {{ opacity: 0; transform: translateY(6px); }}
    to   {{ opacity: 1; transform: translateY(0); }}
  }}

  @media (prefers-reduced-motion: reduce) {{
    main {{ animation: none; }}
  }}

  /* Brand wordmark above the card — same uppercase + wide-tracking
     idiom DS Buttons use. */
  .brand {{
    text-align: center;
    margin-bottom: 1.75rem;
    font-family: 'Rules Compressed', 'Collapse', sans-serif;
    font-weight: 600;
    font-size: 1.05rem;
    letter-spacing: 0.32em;
    text-transform: uppercase;
    color: var(--midground);
  }}
  .brand .dot {{
    display: inline-block;
    width: 6px;
    height: 6px;
    background: var(--midground);
    margin: 0 0.55em 0.18em;
    vertical-align: middle;
    border-radius: 1px;
  }}

  .card {{
    position: relative;
    padding: 2.25rem 2rem 2rem;
    background: color-mix(in srgb, #ffffff 2%, var(--background-base));
    border: 1px solid var(--hairline);
    /* Hairline highlight + bevel shadow — matches DS Button SHADOW_DEFAULT
       (`inset -1px -1px 0 #00000080, inset 1px 1px 0 #ffffff80`) at panel scale. */
    box-shadow:
      inset 1px 1px 0 0 color-mix(in srgb, #ffffff 5%, transparent),
      inset -1px -1px 0 0 rgba(0, 0, 0, 0.4),
      0 24px 60px -20px rgba(0, 0, 0, 0.6);
  }}

  h1 {{
    margin: 0 0 0.4rem;
    font-family: 'Rules Compressed', 'Collapse', sans-serif;
    font-weight: 600;
    font-size: 1.85rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--foreground);
  }}

  .subtitle {{
    margin: 0 0 1.75rem;
    color: color-mix(in srgb, var(--foreground) 65%, transparent);
    font-size: 0.95rem;
  }}

  /* Magic link email form — stacked input + button. */
  .magic-link-form label {{
    display: block;
    margin: 0 0 1.75rem .1rem;
    color: color-mix(in srgb, var(--foreground) 85%, transparent);
    font-size: 0.9rem;
    font-family: 'Collapse', sans-serif;
    font-weight: 600;
    letter-spacing: 0.06em;
  }}

  .magic-link-form input[type="email"] {{
    display: block;
    width: 100%;
    box-sizing: border-box;
    padding: 0.85rem 1rem;
    margin-bottom: 0.75rem;
    background: color-mix(in srgb, var(--foreground) 6%, var(--background-base));
    border: 1px solid var(--hairline-strong);
    color: var(--foreground);
    font-family: 'Collapse', sans-serif;
    font-size: 0.95rem;
    outline: none;
  }}
  .magic-link-form input[type="email"]:focus {{
    border-color: var(--midground);
  }}
  .magic-link-form input[type="email"]::placeholder {{
    color: color-mix(in srgb, var(--foreground) 40%, transparent);
  }}

  .magic-link-status {{
    margin: 0.5rem 0 0;
    font-size: 0.85rem;
    min-height: 1.2em;
    color: color-mix(in srgb, var(--foreground) 70%, transparent);
  }}
  .magic-link-status.success {{
    color: #4ade80;
  }}
  .magic-link-status.error {{
    color: #f87171;
  }}

  .provider-list {{
    display: grid;
    gap: 0.75rem;
  }}

  /* Provider button — mirrors DS Button (default variant):
     amber surface, dark text, uppercase + wide tracking, inset bevel. */
  .provider-btn {{
    display: block;
    width: 100%;
    box-sizing: border-box;
    padding: 0.95rem 1rem;
    text-align: center;
    background: var(--midground);
    color: var(--background-base);
    font-family: 'Collapse', sans-serif;
    font-weight: 700;
    font-size: 0.78rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    text-decoration: none;
    border: 0;
    border-radius: 0;  /* DS Button is squared — no rounded corners. */
    cursor: pointer;
    box-shadow:
      inset 1px 1px 0 0 rgba(255, 255, 255, 0.5),
      inset -1px -1px 0 0 rgba(0, 0, 0, 0.5);
    transition: filter 0.12s ease-out;
  }}
  .provider-btn:hover {{
    filter: brightness(1.08);
  }}
  .provider-btn:active {{
    /* DS Button uses `active:invert` on the default surface. */
    filter: invert(1);
  }}
  .provider-btn:focus-visible {{
    outline: 2px solid var(--midground);
    outline-offset: 3px;
  }}

  footer {{
    margin-top: 1.75rem;
    text-align: center;
    color: color-mix(in srgb, var(--foreground) 45%, transparent);
    font-size: 0.75rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    line-height: 1.7;
  }}
  footer .sep {{
    display: inline-block;
    width: 1.5rem;
    height: 1px;
    background: var(--hairline-strong);
    vertical-align: middle;
    margin: 0 0.6em 0.2em;
  }}

  /* Selection — DS uses midground bg + background text. */
  ::selection {{
    background: var(--midground);
    color: var(--background-base);
  }}
</style>
</head>
<body>
<main>
  <div class="brand">Nous<span class="dot"></span>Research</div>
  <div class="card">
    <h1>Sign in</h1>
    <p class="subtitle">Choose a sign-in method to continue to the Hermes Agent dashboard.</p>
    <div class="provider-list">
{provider_buttons}
    </div>
  </div>
  <footer>
    <span class="sep"></span>Public bind &middot; Auth required<span class="sep"></span>
  </footer>
</main>
{magic_link_js}
{password_script}
</body>
</html>
"""

_MAGIC_LINK_JS = """\
<script>
function handleMagicLink(event, form) {
  event.preventDefault();
  var email = form.querySelector('input[name="email"]').value;
  var next = form.querySelector('input[name="next"]');
  var statusEl = form.querySelector('.magic-link-status');
  var btn = form.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.textContent = 'Sending\u2026';
  statusEl.className = 'magic-link-status';
  statusEl.textContent = '';
  var body = {email: email};
  if (next && next.value) body.next = next.value;
  fetch('/api/auth/magic-link', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(function(r) {
    btn.disabled = false;
    btn.textContent = 'Send magic link';
    if (r.ok) {
      statusEl.className = 'magic-link-status success';
      statusEl.textContent = 'Check your email for a sign-in link.';
    } else {
      statusEl.className = 'magic-link-status error';
      statusEl.textContent = 'Something went wrong. Please try again.';
    }
  }).catch(function() {
    btn.disabled = false;
    btn.textContent = 'Send magic link';
    statusEl.className = 'magic-link-status error';
    statusEl.textContent = 'Network error. Please try again.';
  });
}
</script>
"""

_EMPTY_HTML = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in unavailable — Hermes Agent</title>
<style>
  @font-face {
    font-family: 'Collapse';
    font-style: normal;
    font-weight: 400;
    font-display: swap;
    src: url('/fonts/Collapse-Regular.woff2') format('woff2');
  }
  @font-face {
    font-family: 'Rules Compressed';
    font-style: normal;
    font-weight: 600;
    font-display: swap;
    src: url('/fonts/RulesCompressed-Medium.woff2') format('woff2');
  }
  :root {
    --background-base: #170d02;
    --midground: #ffac02;
    --foreground: #ffffff;
    --hairline: color-mix(in srgb, #ffac02 18%, transparent);
  }
  *, *::before, *::after { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0; min-height: 100%;
    background: var(--background-base);
    color: var(--foreground);
    font-family: 'Collapse', system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    font-size: 16px; line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  body {
    display: grid; place-items: center;
    padding: clamp(1.5rem, 6vh, 6rem) 1.25rem;
  }
  main {
    width: 100%; max-width: 32rem;
    padding: 2.25rem 2rem;
    background: color-mix(in srgb, #ffffff 2%, var(--background-base));
    border: 1px solid var(--hairline);
    box-shadow:
      inset 1px 1px 0 0 color-mix(in srgb, #ffffff 5%, transparent),
      inset -1px -1px 0 0 rgba(0, 0, 0, 0.4),
      0 24px 60px -20px rgba(0, 0, 0, 0.6);
  }
  h1 {
    margin: 0 0 1rem;
    font-family: 'Rules Compressed', 'Collapse', sans-serif;
    font-weight: 600; font-size: 1.5rem;
    letter-spacing: 0.05em; text-transform: uppercase;
    color: var(--midground);
  }
  p { margin: 0 0 1rem; }
  code {
    background: var(--midground);
    color: var(--background-base);
    padding: 0.1em 0.35em;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
  }
</style>
</head>
<body>
<main>
<h1>Sign-in unavailable</h1>
<p>This dashboard is bound to a non-loopback host but no authentication
providers are installed.</p>
<p>Install <code>plugins/dashboard-auth-nous</code> (default) or another
auth provider, or restart with <code>--insecure</code> to bypass the
auth gate (not recommended on untrusted networks).</p>
</main>
</body>
</html>
"""


def render_login_html(*, next_path: str = "") -> str:
    """Return the full HTML for ``GET /login``.

    ``next_path`` — when set, the post-login landing path the user
    originally requested. Threaded into each provider button's ``href``
    as a ``next=`` query parameter so the OAuth round trip carries it
    end-to-end. The caller (``routes.login_page``) is responsible for
    validating ``next_path`` against the same-origin rules before we
    emit it; we still HTML-escape it as defence in depth.

    For OAuth providers, a redirect button is rendered. For magic_link
    providers, an email input form is rendered instead that POSTs to
    ``/api/auth/magic-link``.
    """
    providers = list_providers()
    if not providers:
        return _EMPTY_HTML

    if next_path:
        # URL-encode then HTML-escape. The URL-encode step matches the
        # gate's ``_safe_next_target`` output shape (also URL-encoded),
        # so a value that round-tripped from /login?next=... back into
        # the button href is byte-identical.
        from urllib.parse import quote
        from urllib.parse import unquote
        next_qs = f"&next={html.escape(quote(next_path, safe=''), quote=True)}"
        # For magic link forms, the next value goes in a hidden field
        # so we need the raw HTML-escaped value (not URL-encoded).
        next_hidden = html.escape(next_path)
    else:
        next_qs = ""
        next_hidden = ""

    buttons = []
    needs_password_script = False
    for p in providers:
        if getattr(p, "supports_password", False):
            # Password (non-redirect) provider — render a username/password
            # form. The single delegated submit handler is _PASSWORD_FORM_SCRIPT
            # (loaded once at the bottom if any provider needs it).
            needs_password_script = True
            buttons.append(_render_password_form(p, next_path))
        if getattr(p, "flow_type", "oauth") == "magic_link":
            # Render an email input form for magic link providers.
            buttons.append(
                f'      <form class="magic-link-form" method="post" '
                f'action="/api/auth/magic-link" '
                f'onsubmit="handleMagicLink(event, this)">'
                f'<label for="email-{html.escape(p.name)}">'
                f'{html.escape(p.display_name)}</label>'
                f'<input id="email-{html.escape(p.name)}" name="email" '
                f'type="email" required autocomplete="email" '
                f'placeholder="you@example.com" />'
                f'<input type="hidden" name="next" value="{next_hidden}" />'
                f'<button type="submit" class="provider-btn">Send magic link</button>'
                f'<p class="magic-link-status" id="status-{html.escape(p.name)}"></p>'
                f'</form>'
            )
        else:
            buttons.append(
                f'      <a class="provider-btn" '
                f'href="/auth/login?provider={html.escape(p.name, quote=True)}{next_qs}">'
                f'Sign in with {html.escape(p.display_name)}</a>'
            )

    # Inject the magic link JavaScript if any provider uses magic_link.
    magic_link_js = ""
    if any(getattr(p, "flow_type", "oauth") == "magic_link" for p in providers):
        magic_link_js = _MAGIC_LINK_JS

    # Inject the password form submit handler if any provider needs it.
    password_script = _PASSWORD_FORM_SCRIPT if needs_password_script else ""

    return _LOGIN_HTML_TEMPLATE.format(
        provider_buttons="\n".join(buttons),
        magic_link_js=magic_link_js,
        password_script=password_script,
    )


def _render_password_form(provider, next_path: str) -> str:
    """Render a username/password form for a ``supports_password`` provider.

    The form is wired by :data:`_PASSWORD_FORM_SCRIPT` to POST JSON to
    ``/auth/password-login``. ``next_path`` is HTML-escaped and carried
    in a hidden field. The provider ``name`` is emitted in a ``data-``
    attribute so the script reads it without trusting form-field order.
    """
    pname = html.escape(provider.name, quote=True)
    plabel = html.escape(provider.display_name)
    safe_next = html.escape(next_path, quote=True) if next_path else ""
    return (
        f'      <form class="provider-form" data-provider="{pname}" '
        f'autocomplete="on">\n'
        f'        <div class="form-title">Sign in with {plabel}</div>\n'
        f'        <input type="hidden" name="next" value="{safe_next}">\n'
        f'        <label class="field">\n'
        f'          <span class="field-label">Username</span>\n'
        f'          <input class="field-input" type="text" name="username" '
        f'autocomplete="username" autocapitalize="none" '
        f'autocorrect="off" spellcheck="false" required>\n'
        f'        </label>\n'
        f'        <label class="field">\n'
        f'          <span class="field-label">Password</span>\n'
        f'          <input class="field-input" type="password" name="password" '
        f'autocomplete="current-password" required>\n'
        f'        </label>\n'
        f'        <div class="form-error" role="alert" hidden></div>\n'
        f'        <button class="provider-btn" type="submit">Sign in</button>\n'
        f'      </form>\n'
    )


_PASSWORD_FORM_SCRIPT = """
<script>
(function() {
  function attach() {
    document.querySelectorAll('form.provider-form').forEach(function(form) {
      if (form.dataset.bound === '1') return;
      form.dataset.bound = '1';
      form.addEventListener('submit', async function(ev) {
        ev.preventDefault();
        var provider = form.dataset.provider;
        var next = (form.querySelector('input[name="next"]') || {}).value || '';
        var username = (form.querySelector('input[name="username"]') || {}).value || '';
        var password = (form.querySelector('input[name="password"]') || {}).value || '';
        var errEl = form.querySelector('.form-error');
        if (errEl) { errEl.hidden = true; errEl.textContent = ''; }
        try {
          var r = await fetch('/auth/password-login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'same-origin',
            body: JSON.stringify({provider: provider, username: username, password: password, next: next})
          });
          if (r.ok) { window.location.href = next || '/'; return; }
          var body = await r.json().catch(function() { return {}; });
          if (errEl) { errEl.hidden = false; errEl.textContent = (body.detail || 'Invalid credentials'); }
        } catch (e) {
          if (errEl) { errEl.hidden = false; errEl.textContent = 'Network error'; }
        }
      });
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attach);
  } else {
    attach();
  }
})();
</script>
"""
