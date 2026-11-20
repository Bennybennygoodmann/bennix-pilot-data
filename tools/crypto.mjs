// Encrypts / decrypts the dashboard data with Ben's secret code.
// Same format as the browser (WebCrypto): PBKDF2-SHA256 -> AES-256-GCM.
//
//   BP_CODE=... node tools/crypto.mjs encrypt rows.json data.enc.json
//   BP_CODE=... node tools/crypto.mjs decrypt data.enc.json rows.json
//
// rows.json = { "rows": [ {date, store, sales, revenue_xof, fee_pct, fees_xof,
//                          ad_usd, ad_xof, net_xof, day_status}, ... ] }
import { readFileSync, writeFileSync } from 'node:fs'
import { webcrypto as crypto } from 'node:crypto'

const ITERATIONS = 310000
const b64 = (buf) => Buffer.from(buf).toString('base64')
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'))

async function keyFrom(code, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function encrypt(obj, code) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await keyFrom(code, salt)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)))
  return { v: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) }
}

export async function decrypt(box, code) {
  const key = await keyFrom(code, unb64(box.salt))
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct))
  return JSON.parse(new TextDecoder().decode(pt))
}

const [, , cmd, input, output] = process.argv
if (cmd) {
  const code = process.env.BP_CODE
  if (!code) { console.error('BP_CODE manquant'); process.exit(1) }
  if (cmd === 'encrypt') {
    const data = JSON.parse(readFileSync(input, 'utf8'))
    data.updated = data.updated || new Date().toISOString()
    writeFileSync(output, JSON.stringify(await encrypt(data, code)))
    console.log(data.rows ? `ok: ${data.rows.length} lignes chiffrées` : 'ok: fichier chiffré')
  } else if (cmd === 'decrypt') {
    const data = await decrypt(JSON.parse(readFileSync(input, 'utf8')), code)
    writeFileSync(output, JSON.stringify(data, null, 1))
    console.log(data.rows ? `ok: ${data.rows.length} lignes` : 'ok: fichier déchiffré')
  } else {
    console.error('usage: encrypt|decrypt <in> <out>'); process.exit(1)
  }
}
