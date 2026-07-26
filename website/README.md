# SESAME website

The marketing site for [sesame.del.ma](https://sesame.del.ma), built with
[Tachyon](https://tachyon.del.ma) and styled with
[DuVay](https://duvay.del.ma).

It is a static site: three prerendered pages, no backend, and no data of its
own. DuVay ships as one vendored CSS file under
`client/shared/assets/duvay/`, so the site has no build-time dependency on the
DuVay repository.

## Develop

```bash
bun install
bun run serve
```

The dev server reads `.env` — copy `.env.example` if you do not have one. It
watches `client/` and rebuilds on change.

## Build

```bash
bun run bundle
```

Prerendered output lands in `dist/web/`. Deploy that directory as static
files.

## Layout

```
client/
  pages/            one directory per route: /, /docs, /docs/concepts,
                    /docs/authentication, /docs/mfa, /docs/authorization,
                    /docs/errors, /download
  components/       tac.html for markup, tac.js for behaviour and data
  shared/
    scripts/
      imports.js    browser entry: theme, favicon, SEO metadata, route titles
      facts.js      every number and list the site quotes about SESAME
    assets/
      site.css      the whole site's styling, over DuVay's tokens
      duvay/        vendored duvay.min.css
```

Component styling lives in `site.css` rather than in per-component `tac.css`
files. The site is small enough that one stylesheet is easier to read than a
dozen, and the cascade is easier to reason about when it is in one place.

## Visual language

Three layers give the page depth without an image: a fixed aurora behind the
fold, a masked grid that fades before it reaches the content, and one shared
"lift" ramp — `--lift-border`, `--lift-highlight`, `--lift-shadow` — used by
every raised surface so a card, a code block and a callout sit at the same
height instead of each inventing one. A second accent (`--accent-far`, a
blue) exists so gradients have somewhere to travel; monochrome violet reads as
flat however many layers are stacked on it.

Both themes define the same ramp. Light needs less glow and stronger
hairlines, or every surface dissolves into the page.

One ordering rule matters: **the responsive block is last in the file.** Media
queries add no specificity, so a responsive override only wins if it comes
after the rule it adjusts.

## Responsive behaviour

Most sizing is fluid — `clamp()` on spacing and type — so the media queries
handle only what a clamp cannot: layout that has to change shape, and
affordances that have to grow for a finger.

What changes, and where:

| Width | Change |
| --- | --- |
| ≤ 400px | The wordmark hides; the mark alone identifies the site and the theme/menu controls need the room. |
| ≤ 767px | Header collapses to a menu; the install command wraps so its "copy" label cannot scroll out of reach; reference tables stack into label/value pairs and drop their headings; hero and CTA buttons go full width. |
| ≤ 1023px | The architecture diagram becomes a column and its arrows rotate to point down — left-to-right arrows are wrong once the nodes stack. |
| ≥ 1440px | Prose stays at a 52rem measure; reference tables and card grids widen to 78rem rather than leaving a metre of empty screen. |
| `pointer: coarse` or ≤ 767px | Every button and tab is at least 44px tall. Both conditions, because a browser in responsive mode reports a fine pointer at phone widths. |
| `prefers-reduced-motion` | Smooth scrolling and card transitions are dropped. |

Two rules exist for non-obvious reasons, and are commented in place:

- `body { overflow-x: clip }` — not `hidden`, which would make the body a
  scroll container and silently break the sticky header.
- `body > div:has(> .site-header) { display: contents }` — Tachyon wraps each
  component in its own element, and a sticky child can only travel within its
  parent. Without this the wrapper is exactly as tall as the header, so
  `position: sticky` does nothing.

### Re-checking it

There is no automated visual suite. To re-audit after a layout change, serve
the site, open it, and run this in the console at each width — it reports
anything that pushes the page sideways and any control too small to tap:

```js
const PAGES = ['/', '/docs', '/docs/concepts', '/docs/authentication',
               '/docs/mfa', '/docs/authorization', '/docs/errors', '/download']
const sleep = ms => new Promise(r => setTimeout(r, ms))
const results = {}
for (const path of PAGES) {
    const a = document.createElement('a')
    a.href = path; document.body.appendChild(a); a.click(); a.remove()
    await sleep(400)
    const w = document.documentElement.clientWidth
    const over = []
    for (const el of document.querySelectorAll('body *')) {
        const r = el.getBoundingClientRect()
        if (r.width === 0) continue
        let scroller = false
        for (let p = el.parentElement; p; p = p.parentElement) {
            if (getComputedStyle(p).overflowX === 'auto') { scroller = true; break }
        }
        if (!scroller && r.right > w + 1) over.push(el.tagName.toLowerCase())
    }
    const small = [...document.querySelectorAll('a.w-btn, button, [role=tab]')]
        .filter(e => { const r = e.getBoundingClientRect(); return r.height > 0 && r.height < 40 }).length
    results[path] = { sideScroll: document.documentElement.scrollWidth - w, over: [...new Set(over)], small }
}
console.table(results)
```

Wide children — code blocks — are meant to scroll inside their own container,
so the check ignores anything inside an `overflow-x: auto` ancestor. Verified
clean at 320, 375, 414, 768, 834, 1024, 1920, and 2560 across all eight pages.

## Claims are tested

`facts.js` is the single source of truth for everything countable — the
operation count, the SDK list, and the two-column
"what is built / what is not" copy on the homepage.

It is not decoration. `test/contract/website_test.go` in the parent repository
joins it back to the sources it describes, and fails if:

- the advertised operation count differs from `api/machine/v1/operations.json`;
- the site names an SDK that is not in `clients/`, or omits one that is;
- a guide snippet calls an SDK method no shim of that naming convention
  defines, or a guide card links to a route the site does not serve;
- the error reference documents a code the engine cannot return, or omits one
  it can;
- any page contains a support claim SESAME has not earned — "OpenID
  certified", "production ready", "battle tested", and similar.

Those tests run as part of `go test ./...`. A marketing site is where a
security project quietly starts overstating itself, so the copy is wired into
the same drift detection as the protocol surface.

If you change a number here, change it in `facts.js` and let the test tell you
whether the repository agrees.
