import { PLATFORMS } from '../../shared/scripts/facts.js'

const TITLE = 'Download — SESAME'
document.title = TITLE

export default class extends Tac {
  platforms = PLATFORMS

  constructor(props = {}, tac = undefined) {
    super(props, tac)
    if (this.isBrowser) document.title = TITLE
  }
}
