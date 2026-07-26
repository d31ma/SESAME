import { SDK_COUNT } from '../../shared/scripts/facts.js'

export default class extends Tac {
  // The lede reads "in any of {sdkCount} languages" — the number of shims
  // that can drive the engine directly.
  sdkCount = SDK_COUNT

  installCmd = 'go install github.com/d31ma/sesame/cmd/sesame@latest'
  installCopied = false

  ticks = [
    'No network listener',
    'One direct dependency',
    'Default deny, always',
    'Apache-2.0',
  ]

  async copyInstall() {
    try {
      await navigator.clipboard.writeText(this.installCmd)
      this.installCopied = true
      setTimeout(() => {
        this.installCopied = false
      }, 2200)
    } catch (_) {
      /* clipboard unavailable — the hint text stays */
    }
    return this.installCmd
  }
}
