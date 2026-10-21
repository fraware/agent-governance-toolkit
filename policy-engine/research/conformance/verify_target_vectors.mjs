/** Independent Node.js verifier for the frozen effect-target-v1 research profile.
 * Built-in crypto only. The externally trusted public-key fingerprint is a
 * caller premise, never derived from an untrusted observation.
 */
import { createHash, createPublicKey, timingSafeEqual, verify as edVerify } from 'node:crypto';

const ACTION_KEYS = ['action_id', 'operation', 'resource', 'subject', 'tenant', 'value'];
const RECEIPT_KEYS = ['action_id', 'action_sha256', 'kind', 'nonce', 'observed_at', 'state', 'version'];
const DOMAIN = Buffer.from('ACS-EFFECT-TARGET-OBSERVATION-v1\0', 'ascii');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function objectKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && Object.keys(value).every(key => keys.includes(key));
}
function validAction(action) {
  return objectKeys(action, ACTION_KEYS) && ACTION_KEYS.every(key => typeof action[key] === 'string')
    && action.action_id.length !== 0;
}
function validDigest(value) { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
function jsonStringAscii(value) {
  // Python json.dumps(..., ensure_ascii=True) escaping for this scalar profile.
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, ch =>
    `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
export function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return jsonStringAscii(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return `{${Object.keys(value).sort().map(key =>
      `${jsonStringAscii(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new TypeError('noncanonical scalar profile');
}
function sha256Hex(value) { return createHash('sha256').update(value).digest('hex'); }
function strictBase64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.toString('base64') === value ? bytes : null;
}
export function appraise({action, nonce, receipt, publicKeyHex, expectedKeySha256}) {
  try {
    if (!validAction(action) || typeof nonce !== 'string' || nonce.length === 0) return 'undetermined';
    if (typeof publicKeyHex !== 'string' || !/^[0-9a-f]{64}$/.test(publicKeyHex)) return 'undetermined';
    if (typeof expectedKeySha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expectedKeySha256)) return 'undetermined';
    const pub = Buffer.from(publicKeyHex, 'hex');
    if (!timingSafeEqual(Buffer.from(sha256Hex(pub), 'hex'), Buffer.from(expectedKeySha256, 'hex'))) return 'undetermined';
    if (!objectKeys(receipt, ['payload', 'signature'])) return 'undetermined';
    const p = receipt.payload;
    if (!objectKeys(p, RECEIPT_KEYS) || p.version !== 1 || p.kind !== 'target_state_snapshot'
        || typeof p.action_id !== 'string' || p.action_id !== action.action_id
        || typeof p.nonce !== 'string' || p.nonce !== nonce
        || !Number.isSafeInteger(p.observed_at) || p.observed_at < 0
        || (p.state !== 'committed' && p.state !== 'absent')) return 'undetermined';
    if ((p.state === 'absent' && p.action_sha256 !== null)
        || (p.state === 'committed' && !validDigest(p.action_sha256))) return 'undetermined';
    const sig = strictBase64(receipt.signature);
    if (sig === null || sig.length !== 64) return 'undetermined';
    const key = createPublicKey({key: Buffer.concat([SPKI_PREFIX, pub]), format: 'der', type: 'spki'});
    const msg = Buffer.concat([DOMAIN, Buffer.from(canonical(p), 'ascii')]);
    if (!edVerify(null, msg, key, sig)) return 'undetermined';
    if (p.state === 'absent') return 'refuted';
    return p.action_sha256 === sha256Hex(Buffer.from(canonical(action), 'ascii'))
      ? 'established' : 'refuted';
  } catch {
    return 'undetermined';
  }
}
export const PROFILE_DOMAIN_HEX = DOMAIN.toString('hex');
export function actionSha256(action) {
  if (!validAction(action)) throw new TypeError('invalid action');
  return sha256Hex(Buffer.from(canonical(action), 'ascii'));
}
