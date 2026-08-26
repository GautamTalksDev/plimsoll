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
footer{
  margin-top:4rem; padding-top:1.5rem; border-top:1px solid var(--line);
  color:var(--muted); font-size:13px;
}
`
