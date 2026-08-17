/**
 * The seam's sign-in page: one self-contained HTML document, served for any
 * provider that verifies a submitted secret.
 *
 * The only value interpolated into the markup is this package's own sign-in
 * path constant, so no deployment or request value can reach it, and the page
 * loads no external resource. Failure text is rendered by the page from the
 * sign-in response rather than substituted server-side.
 * @module @deepseek-ai/dsh-host-web-auth/login-page
 */

import { SIGN_IN_PATH } from './paths.ts'

/** The full sign-in document, served at {@link LOGIN_PATH}. */
export const LOGIN_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign in — DeepSeek Harness</title>
<style>
  :root { color-scheme: light dark; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  form { width: min(22rem, calc(100vw - 3rem)); display: grid; gap: 0.75rem; }
  h1 { margin: 0; font-size: 1.1rem; font-weight: 600; }
  p { margin: 0; opacity: 0.7; font-size: 0.9rem; }
  input, button {
    font: inherit; padding: 0.55rem 0.7rem; border-radius: 0.4rem;
    border: 1px solid color-mix(in oklab, currentColor 35%, transparent);
    background: transparent; color: inherit;
  }
  button { cursor: pointer; font-weight: 600; }
  button[disabled] { cursor: progress; opacity: 0.6; }
  [role="alert"]:empty { display: none; }
  [role="alert"] { color: #d33; font-size: 0.9rem; }
</style>
</head>
<body>
<form id="f">
  <h1>DeepSeek Harness</h1>
  <p>This harness requires sign-in for remote access.</p>
  <input id="s" type="password" name="secret" autocomplete="current-password"
         aria-label="Password" placeholder="Password" required autofocus>
  <button id="b" type="submit">Sign in</button>
  <div id="e" role="alert"></div>
</form>
<script>
(function () {
  var form = document.getElementById('f')
  var secret = document.getElementById('s')
  var button = document.getElementById('b')
  var error = document.getElementById('e')
  form.addEventListener('submit', function (event) {
    event.preventDefault()
    error.textContent = ''
    button.disabled = true
    fetch(${JSON.stringify(SIGN_IN_PATH)}, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ secret: secret.value }),
    }).then(function (response) {
      return response.json().then(function (body) { return { status: response.status, body: body } })
    }).then(function (result) {
      if (result.status === 200) {
        // Same-document replace: the token is in an HttpOnly cookie, so the
        // shell simply reloads with it attached.
        var next = new URL(location.href).searchParams.get('next')
        location.replace(next && next.charAt(0) === '/' && next.charAt(1) !== '/' ? next : '/')
        return
      }
      button.disabled = false
      secret.value = ''
      secret.focus()
      error.textContent = typeof result.body.message === 'string' ? result.body.message : 'Sign-in failed.'
    }).catch(function () {
      button.disabled = false
      error.textContent = 'Sign-in request failed.'
    })
  })
})()
</script>
</body>
</html>
`
