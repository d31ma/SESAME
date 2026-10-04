export default class extends Tac {
  installCmd = 'go install github.com/d31ma/sesame/cmd/sesame@latest'
  installCopied = false

  ticks = [
    'Engine opens no port',
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
