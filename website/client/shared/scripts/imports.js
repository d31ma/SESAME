// Browser entry — owns the theme lifecycle and injects the favicon and SEO
// metadata into the generated shell. The site is authored entirely with
// DuVay's CSS classes and no web components, so only duvay.min.css is needed.
const THEME_KEY = 'w-theme'
const THEME_ICON = { dark: '☾', light: '☀' }

function applyTheme(theme) {
    document.documentElement.setAttribute('w-theme', theme)
    try {
        localStorage.setItem(THEME_KEY, theme)
    } catch (_) {}
    for (const el of document.querySelectorAll('[w-theme-icon]')) {
        el.textContent = THEME_ICON[theme] || THEME_ICON.dark
    }
}

function currentTheme() {
    try {
        return localStorage.getItem(THEME_KEY) || 'dark'
    } catch (_) {
        return 'dark'
    }
}

if (typeof document !== 'undefined') {
    // Apply the persisted theme before first paint; SESAME defaults to dark.
    applyTheme(currentTheme())

    // Delegated toggles — these survive any Tac rerender because nothing is
    // bound to a node that a rerender can replace.
    const closeMenu = () => {
        const header = document.querySelector('.site-header')
        if (!header || !header.classList.contains('menu-open')) return
        header.classList.remove('menu-open')
        header.querySelector('[w-menu-toggle]')?.setAttribute('aria-expanded', 'false')
    }
    document.addEventListener('click', (event) => {
        if (event.target.closest('[w-theme-toggle]')) {
            applyTheme(currentTheme() === 'dark' ? 'light' : 'dark')
            return
        }
        const burger = event.target.closest('[w-menu-toggle]')
        if (burger) {
            const header = burger.closest('.site-header')
            const open = header.classList.toggle('menu-open')
            burger.setAttribute('aria-expanded', String(open))
            return
        }
        // Any other click, including a menu link, closes an open mobile menu.
        closeMenu()
    })
    window.addEventListener('popstate', closeMenu)

    // Keep <title> in sync with the route. SPA navigation does not re-run page
    // constructors, so a page's own `document.title` only fires the first time
    // its module loads — after that the title would stick. Drive it here.
    const ROUTE_TITLES = {
        '/': 'SESAME — Identity your application owns.',
        '/docs': 'Docs — SESAME',
        '/docs/concepts': 'Concepts — SESAME',
        '/docs/authentication': 'Authentication and tokens — SESAME',
        '/docs/authorization': 'Authorization — SESAME',
        '/docs/errors': 'Reason and error codes — SESAME',
        '/docs/mfa': 'MFA and step-up — SESAME',
        '/docs/oauth-flows': 'Device grant, PAR, and DPoP — SESAME',
        '/download': 'Download — SESAME'
    }
    const syncTitle = () => {
        const title = ROUTE_TITLES[location.pathname.replace(/\/$/, '') || '/']
        if (title && document.title !== title) document.title = title
    }
    window.addEventListener('tachyon:navigate', syncTitle)
    window.addEventListener('popstate', syncTitle)
    syncTitle()

    // Mark the documentation link for the page being read. Computed from the
    // DOM rather than at render time, because a component that decided this
    // once would be right on first paint and wrong after every SPA hop.
    const syncDocsNav = () => {
        const here = location.pathname.replace(/\/$/, '') || '/'
        for (const link of document.querySelectorAll('.docs-sidebar-list a')) {
            const current = new URL(link.href, location.origin).pathname
                .replace(/\/$/, '') === here
            link.classList.toggle('is-current', current)
            // Absent rather than "false": aria-current is a token, and the
            // string "false" is a value assistive technology has to guess at.
            if (current) link.setAttribute('aria-current', 'page')
            else link.removeAttribute('aria-current')
        }
    }
    window.addEventListener('tachyon:navigate', syncDocsNav)
    window.addEventListener('popstate', syncDocsNav)
    syncDocsNav()

    // Collapse the docs nav behind a button on narrow screens.
    document.addEventListener('click', (event) => {
        const toggle = event.target.closest('[w-docs-toggle]')
        if (!toggle) return
        const sidebar = toggle.closest('.docs-sidebar')
        const open = sidebar.classList.toggle('is-open')
        toggle.setAttribute('aria-expanded', String(open))
    })

    // A Tac rerender can rebuild the header and its [w-theme-icon] span.
    new MutationObserver(() => {
        syncDocsNav()
        const theme = currentTheme()
        for (const el of document.querySelectorAll('[w-theme-icon]')) {
            if (el.textContent !== (THEME_ICON[theme] || THEME_ICON.dark)) {
                el.textContent = THEME_ICON[theme] || THEME_ICON.dark
            }
        }
    }).observe(document.documentElement, { childList: true, subtree: true })

    // Favicon — the SESAME mark: a keyhole in a closed door.
    const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#8b7cf6"/><rect x="14" y="12" width="36" height="40" rx="7" fill="#100b26"/><circle cx="32" cy="27" r="7" fill="none" stroke="#8b7cf6" stroke-width="4"/><path d="M28.8 33.5 26.5 45h11l-2.3-11.5" fill="none" stroke="#8b7cf6" stroke-width="4" stroke-linejoin="round"/></svg>`
    const favicon = document.createElement('link')
    favicon.rel = 'icon'
    favicon.type = 'image/svg+xml'
    favicon.href = 'data:image/svg+xml,' + encodeURIComponent(faviconSVG)
    document.head.appendChild(favicon)

    // Description copy is deliberately conservative: this is a developer
    // preview, and a search result is a support claim like any other.
    const DESCRIPTION =
        'SESAME is an open-source, headless authentication and authorization engine backed by FYLO. It opens no network listener — your application owns every route and drives the engine over a versioned stdin/stdout protocol. OIDC provider, passkeys, TOTP, deterministic default-deny authorization, inbound OIDC and SAML federation, and SCIM provisioning, with drop-in clients for ten languages.'
    const seoMeta = [
        { name: 'description', content: DESCRIPTION },
        {
            name: 'keywords',
            content:
                'sesame, identity, authentication, authorization, oidc, oauth, saml, scim, passkeys, webauthn, self-hosted, headless, open source, fylo'
        },
        { name: 'author', content: 'SESAME contributors' },
        { name: 'robots', content: 'index, follow' },
        { property: 'og:type', content: 'website' },
        { property: 'og:title', content: 'SESAME — Identity your application owns.' },
        {
            property: 'og:description',
            content:
                'A headless identity and authorization engine that opens no port. Your application owns every listener; SESAME owns every security decision.'
        },
        { property: 'og:url', content: 'https://sesame.del.ma' },
        { property: 'og:site_name', content: 'SESAME' },
        { name: 'twitter:card', content: 'summary' },
        { name: 'twitter:title', content: 'SESAME — Identity your application owns.' },
        {
            name: 'twitter:description',
            content:
                'A headless identity and authorization engine that opens no port. Your application owns every listener; SESAME owns every security decision.'
        }
    ]
    for (const attrs of seoMeta) {
        const meta = document.createElement('meta')
        for (const [key, value] of Object.entries(attrs)) meta.setAttribute(key, value)
        document.head.appendChild(meta)
    }
}
