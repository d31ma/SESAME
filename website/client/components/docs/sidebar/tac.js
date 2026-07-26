import { DOCS_SECTIONS } from '../../../shared/scripts/docs-nav.js'

// The documentation sidebar.
//
// It renders from the shared map so it cannot drift from the guide grid on
// /docs. It holds no state: the current-page highlight and the mobile
// disclosure are both driven from imports.js against the DOM, because SPA
// navigation does not re-run page constructors — a highlight computed here
// would be correct on first paint and then stick to whichever page loaded
// first.
export default class extends Tac {
  sections = DOCS_SECTIONS
}
