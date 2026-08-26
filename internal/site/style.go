// Copyright 2026 The PLIMSOLL Authors
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package site

// StyleCSS is the site stylesheet. It is served at /site.css and referenced
// with an absolute path because pages are generated at varying depths.
//
// It is a file rather than an inline <style> block so the published CSP can
// forbid inline styles. No webfonts, no external resources: the site makes the
// same zero-egress promise the CLI does.
const StyleCSS = `:root{
  --bg:#fbfbfa; --fg:#1a1a19; --muted:#5f5e5a; --line:#e3e2dd;
  --panel:#ffffff; --accent:#0f6e56; --code-bg:#f4f3f0;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#191917; --fg:#e8e7e2; --muted:#a3a29b; --line:#33322e;
    --panel:#211f1d; --accent:#5dcaa5; --code-bg:#252320;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
  background:var(--bg); color:var(--fg);
  max-width:46rem; margin:0 auto; padding:2rem 1.25rem 5rem;
  line-height:1.65; font-size:16px;
}
nav{
  display:flex; flex-wrap:wrap; gap:1.25rem;
  padding-bottom:1rem; margin-bottom:2.5rem;
  border-bottom:1px solid var(--line); font-size:14px;
}
nav a{color:var(--muted); text-decoration:none}
nav a:hover{color:var(--fg); text-decoration:underline}
h1{font-size:1.75rem; font-weight:600; line-height:1.25; margin:0 0 1rem; letter-spacing:-0.01em}
h2{font-size:1.15rem; font-weight:600; margin:2.5rem 0 .75rem}
p{margin:0 0 1rem}
a{color:var(--accent)}
.lede{font-size:1.05rem; color:var(--muted)}
.callout{
  border-left:3px solid var(--accent); border-radius:0;
  background:var(--panel); padding:1rem 1.25rem; margin:1.5rem 0;
}
.callout p:last-child{margin-bottom:0}
table{border-collapse:collapse; width:100%; margin:1.25rem 0; font-size:14px}
th,td{text-align:left; padding:.6rem .75rem; border-bottom:1px solid var(--line); vertical-align:top}
th{font-weight:600; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em}
tbody tr:hover{background:var(--panel)}
code,pre{
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:var(--code-bg); font-size:13px;
}
code{padding:.15rem .35rem; border-radius:3px; word-break:break-all}
pre{padding:1rem; border-radius:6px; overflow-x:auto; border:1px solid var(--line)}
pre code{background:none; padding:0; word-break:normal}
td code{font-size:12px}
.empty{color:var(--muted); font-style:italic}
h4{font-size:1rem; font-weight:500; margin:1.5rem 0 .5rem; color:var(--muted)}
hr{border:0; border-top:1px solid var(--line); margin:2rem 0}
ul{padding-left:1.25rem; margin:0 0 1rem}
li{margin:.25rem 0}
strong{font-weight:600}
table th{white-space:nowrap}
footer{
  margin-top:4rem; padding-top:1.5rem; border-top:1px solid var(--line);
  color:var(--muted); font-size:13px;
}
`

// FaviconSVG is served at /favicon.svg. A plumb line: a fixed vertical with a
// weight at the bottom, which is the product. Monochrome via currentColor so
// it reads in both light and dark browser chrome.
const FaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<rect width="32" height="32" rx="6" fill="#0f6e56"/>
<line x1="16" y1="5" x2="16" y2="19" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/>
<path d="M16 19 L21 23 L16 28 L11 23 Z" fill="#ffffff"/>
</svg>
`
