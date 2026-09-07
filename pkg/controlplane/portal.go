// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package controlplane

import "net/http"

type portalView struct {
	Provider             *ProviderStatus
	CSRF                 string
	AuthenticationFailed bool
	Unavailable          bool
}

func (server *Server) renderPortal(response http.ResponseWriter, status int, view portalView) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.WriteHeader(status)
	_ = server.template.Execute(response, view)
}

const portalHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudRING · Development provider</title><link rel="stylesheet" href="/assets/portal.css"></head>
<body><main><header><a class="brand" href="/" aria-label="CloudRING home"><span class="ring" aria-hidden="true"></span>CloudRING</a><span class="badge">Development</span></header>
{{if .Unavailable}}<section class="card"><p class="eyebrow">Provider unavailable</p><h1>Waiting for durable state</h1><p>The database or installation identity could not be verified. Retry after the installation is healthy.</p><a class="button" href="/">Check again</a></section>
{{else if .Provider}}<section class="intro"><p class="eyebrow">Your development provider</p><h1>A place to build.</h1><p>This isolated installation is ready for integration work.</p></section>
<section class="card"><div class="card-heading"><h2>Installation</h2><span class="ready">Ready</span></div><dl><div><dt>Installation</dt><dd>{{.Provider.InstallationID}}</dd></div><div><dt>Operator</dt><dd>{{.Provider.OperatorID}}</dd></div><div><dt>Created</dt><dd><time>{{.Provider.CreatedAt.Format "02 Jan 2006, 15:04 UTC"}}</time></dd></div><div><dt>Database</dt><dd>Connected · writable</dd></div></dl></section>
<section class="card empty"><div class="empty-mark" aria-hidden="true">+</div><h2>No products installed</h2><p>Your provider starts empty. Product installation becomes available as the platform develops.</p></section>
<footer><p>Development environment · Production use is not supported.</p><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="text-button" type="submit">Sign out</button></form></footer>
{{else}}<section class="intro"><p class="eyebrow">Your development provider</p><h1>Start with a clean slate.</h1><p>Sign in to inspect this isolated CloudRING installation.</p></section><section class="card login"><h2>Development operator</h2><p>Use the access key created for this installation.</p>{{if .AuthenticationFailed}}<p class="error" role="alert">The access key or session is invalid. Please sign in again.</p>{{end}}<form method="post" action="/login"><label for="token">Development access key</label><input id="token" name="token" type="password" autocomplete="off" required minlength="64" maxlength="64" pattern="[a-f0-9]{64}" spellcheck="false"><button class="button" type="submit">Sign in</button></form></section><footer><p>Development environment · Production use is not supported.</p></footer>{{end}}
</main></body></html>`

const portalCSS = `:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172b31;background:#f5f7f5;font-synthesis:none;color-scheme:light}*{box-sizing:border-box}body{margin:0}main{max-width:880px;margin:auto;padding:34px 28px 48px}header{display:flex;align-items:center;justify-content:space-between;padding-bottom:36px;border-bottom:1px solid #dce3dd}.brand{display:flex;align-items:center;gap:12px;color:inherit;text-decoration:none;font-size:23px;font-weight:750;letter-spacing:-.7px}.ring{height:27px;width:27px;border:6px solid #147d62;border-radius:50%;box-shadow:inset 0 0 0 3px #f5f7f5}.badge{font-size:12px;font-weight:650;color:#7b571b;background:#f6ebd4;border:1px solid #e9d6b0;border-radius:6px;padding:6px 10px}.intro{padding:44px 0 26px}.eyebrow{text-transform:uppercase;font-size:11px;font-weight:750;letter-spacing:1.6px;color:#4d6b62}h1{font-size:42px;letter-spacing:-1.6px;line-height:1.12;margin:14px 0 15px;font-weight:680}p{font-size:15px;line-height:1.65;color:#52666a}h2{font-size:17px;font-weight:680;margin:0}.card{background:#fff;border:1px solid #dce3dd;border-radius:12px;padding:28px;margin-top:20px}.card-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}.ready{font-size:12px;color:#116645;background:#e6f4e9;border-radius:30px;padding:5px 11px}.ready:before{content:"";display:inline-block;border-radius:50%;background:#23855c;width:6px;height:6px;margin-right:7px}dl{margin:25px 0 0}dl div{display:grid;grid-template-columns:140px 1fr;gap:18px;padding:12px 0;border-top:1px solid #eef1ed}dt{font-size:13px;color:#667b7e}dd{font-size:13px;margin:0;overflow-wrap:anywhere}.empty{text-align:center;padding:36px 30px}.empty p{max-width:360px;margin:10px auto 0;font-size:14px}.empty-mark{width:36px;height:36px;display:grid;place-items:center;margin:0 auto 16px;font-size:22px;color:#6d8278;background:#f1f5f0;border:1px solid #e1e9df;border-radius:9px}footer{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-top:24px}footer p{font-size:12px;color:#70807b}.text-button{background:none;color:#365b50;border:0;font:inherit;font-size:13px;text-decoration:underline;cursor:pointer}.login{max-width:520px;margin-top:4px}.login p{font-size:14px;margin:12px 0 24px}label{display:block;font-size:13px;font-weight:600;margin:0 0 9px}input[type=password]{display:block;width:100%;height:44px;border:1px solid #bbc9c0;border-radius:7px;padding:10px 12px;font:inherit;margin-bottom:20px;outline:none}input:focus{border-color:#147d62;box-shadow:0 0 0 3px #147d6220}.button{display:inline-block;border:0;border-radius:7px;background:#147d62;color:white;font:inherit;font-size:14px;font-weight:650;padding:12px 22px;text-decoration:none;cursor:pointer}.button:hover{background:#0e6850}.button:focus-visible,a:focus-visible,button:focus-visible{outline:3px solid #72b8a4;outline-offset:3px}.error{color:#a23030!important;background:#fff2ef;padding:12px;border:1px solid #f3d3cc;border-radius:6px}@media(max-width:560px){main{padding:24px 18px}h1{font-size:34px}.card{padding:22px}dl div{grid-template-columns:1fr;gap:5px}footer{align-items:flex-start;flex-direction:column;gap:0}header{padding-bottom:25px}.intro{padding-top:30px}}`
