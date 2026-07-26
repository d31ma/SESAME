import { OPERATION_COUNT, SDK_COUNT } from '../../../shared/scripts/facts.js'

export default class extends Tac {
  stats = [
    { value: String(OPERATION_COUNT), label: 'protocol operations' },
    { value: String(SDK_COUNT), label: 'language SDKs' },
    // The engine links golang.org/x/crypto for Argon2id and nothing else of
    // its own; x/sys arrives transitively. A test inspects the linked
    // dependency graph and fails if a third module appears.
    { value: '1', label: 'direct dependency' },
    { value: '0', label: 'ports opened' },
  ]
}
