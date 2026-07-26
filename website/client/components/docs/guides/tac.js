import { DOCS_LINKS } from '../../../shared/scripts/docs-nav.js'

// The guide grid on /docs.
//
// It renders from the same map as the sidebar. It used to hold its own copy of
// the list, which is how a site ends up with a guide the sidebar never shows.
// "Get started" is dropped because this grid sits on that page.
export default class extends Tac {
  guides = DOCS_LINKS.filter((link) => link.href !== '/docs')
}
