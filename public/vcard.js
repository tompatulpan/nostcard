/**
 * vcard.js — vCard 3.0 builder and minimal parser
 *
 * Supports the fields needed for personal contact sharing:
 *   FN, N, TEL, EMAIL, ORG, TITLE, URL, ADR, NOTE, KEY, SOURCE
 *
 * vCard 3.0 (RFC 2426) is used for maximum compatibility with iOS and Android
 * native Contacts apps. vCard 4.0 is not reliably supported by iOS.
 *
 * The SOURCE field is populated with the canonical card URL (without fragment)
 * so recipients' native clients can optionally auto-refresh.
 */

/**
 * Build a vCard 3.0 string from a plain fields object.
 *
 * @param {Object} fields
 * @param {string}   fields.fn          Full name (required)
 * @param {string}   [fields.firstName]
 * @param {string}   [fields.lastName]
 * @param {string[]} [fields.tel]        Array of phone numbers
 * @param {string[]} [fields.email]      Array of email addresses
 * @param {string}   [fields.org]
 * @param {string}   [fields.title]
 * @param {string}   [fields.url]
 * @param {string}   [fields.note]
 * @param {string}   [fields.pgpKey]     Base64-encoded OpenPGP/Autocrypt v2 cert
 * @param {string}   [fields.sourceUrl]  Canonical URL (no fragment) for SOURCE
 * @returns {string}  vCard 3.0 text
 */
export function buildVCard(fields) {
  const lines = ['BEGIN:VCARD', 'VERSION:3.0'];

  // FN (required by RFC 6350)
  lines.push(`FN:${escape(fields.fn || '')}`);

  // N: Last;First;;;
  const last  = fields.lastName  || '';
  const first = fields.firstName || '';
  if (last || first) {
    lines.push(`N:${escape(last)};${escape(first)};;;`);
  }

  // TEL — supports {value, type} objects and legacy plain strings
  for (const tel of (fields.tel || [])) {
    const val  = typeof tel === 'string' ? tel : tel.value;
    const type = typeof tel === 'string' ? 'CELL' : (tel.type || 'cell').toUpperCase();
    if (val && val.trim()) lines.push(`TEL;TYPE=${type}:${val.trim()}`);
  }

  // EMAIL — vCard 3.0 requires INTERNET as base type; add semantic label as second value
  for (const email of (fields.email || [])) {
    const val  = typeof email === 'string' ? email : email.value;
    const type = typeof email === 'string' ? null : email.type;
    if (val && val.trim()) {
      const label = type && type !== 'other'
        ? `INTERNET,${type.toUpperCase()}`
        : 'INTERNET';
      lines.push(`EMAIL;TYPE=${label}:${val.trim()}`);
    }
  }

  // ORG — supports array and legacy single string
  for (const org of (Array.isArray(fields.org) ? fields.org : (fields.org ? [fields.org] : []))) {
    if (org && org.trim()) lines.push(`ORG:${escape(org.trim())}`);
  }

  // TITLE — supports array and legacy single string
  for (const title of (Array.isArray(fields.title) ? fields.title : (fields.title ? [fields.title] : []))) {
    if (title && title.trim()) lines.push(`TITLE:${escape(title.trim())}`);
  }

  // URL — supports {value, type} objects, arrays, and legacy single string
  for (const url of (Array.isArray(fields.url) ? fields.url : (fields.url ? [{ value: fields.url, type: '' }] : []))) {
    const val  = typeof url === 'string' ? url : url.value;
    const type = typeof url === 'string' ? null : url.type;
    if (val && val.trim()) {
      const typeParam = type && type !== 'other' ? `;TYPE=${type.toUpperCase()}` : '';
      lines.push(`URL${typeParam}:${val.trim()}`);
    }
  }

  // NOTE — supports array and legacy single string
  for (const note of (Array.isArray(fields.note) ? fields.note : (fields.note ? [fields.note] : []))) {
    if (note && note.trim()) lines.push(`NOTE:${escape(note.trim())}`);
  }

  // KEY (OpenPGP) — vCard 3.0 encoding (data: URI syntax is vCard 4.0 only)
  if (fields.pgpKey && fields.pgpKey.trim()) {
    lines.push(`KEY;TYPE=PGP;ENCODING=b:${fields.pgpKey.trim()}`);
  }

  // SOURCE — canonical URL without fragment, for native client auto-refresh
  if (fields.sourceUrl && fields.sourceUrl.trim()) {
    lines.push(`SOURCE:${fields.sourceUrl.trim()}`);
  }

  lines.push('END:VCARD');
  return lines.join('\r\n');
}

/**
 * Parse a vCard 4.0 (or 3.0) text string into a plain fields object.
 * Returns the same shape as the input to buildVCard, so the result can be
 * fed back into buildVCard after editing.
 *
 * @param {string} text
 * @returns {Object} fields
 */
export function parseVCard(text) {
  // Unfold continuation lines (RFC 6350 §3.2)
  const unfolded = text.replace(/\r\n[ \t]/g, '').replace(/\n[ \t]/g, '');
  const lines = unfolded.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  const fields = { tel: [], email: [], org: [], title: [], url: [], note: [] };

  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;

    const prop  = line.substring(0, colon).toUpperCase();
    const value = line.substring(colon + 1);

    // Prop may contain parameters: TEL;TYPE=CELL → strip params for matching
    const propName = prop.split(';')[0];

    switch (propName) {
      case 'FN':
        fields.fn = unescape(value);
        break;
      case 'N': {
        const parts = value.split(';');
        fields.lastName  = unescape(parts[0] || '');
        fields.firstName = unescape(parts[1] || '');
        break;
      }
      case 'TEL': {
        const telType = (prop.match(/TYPE=([^;:,]+)/i) || [])[1];
        if (value.trim()) fields.tel.push({ value: value.trim(), type: (telType || 'cell').toLowerCase() });
        break;
      }
      case 'EMAIL': {
        // TYPE may be multi-value: TYPE=INTERNET,HOME — extract semantic label, skip 'internet'
        const typeMatch = (prop.match(/TYPE=([^;:]+)/i) || [])[1];
        const types = typeMatch ? typeMatch.split(',').map(t => t.toLowerCase().trim()) : [];
        // Default to 'other' (not 'work') when no semantic label is present,
        // so the roundtrip 'other' → no TYPE param → parse → 'other' is preserved.
        const emailType = types.find(t => t !== 'internet') || 'other';
        if (value.trim()) fields.email.push({ value: value.trim(), type: emailType });
        break;
      }
      case 'ORG':
        if (value.trim()) fields.org.push(unescape(value.split(';')[0]));
        break;
      case 'TITLE':
        if (value.trim()) fields.title.push(unescape(value));
        break;
      case 'URL': {
        const urlType = (prop.match(/TYPE=([^;:,]+)/i) || [])[1];
        // Default to 'other' (not 'work') when no TYPE is present,
        // so the roundtrip 'other' → no TYPE param → parse → 'other' is preserved.
        if (value.trim()) fields.url.push({ value: value.trim(), type: (urlType || 'other').toLowerCase() });
        break;
      }
      case 'NOTE':
        if (value.trim()) fields.note.push(unescape(value));
        break;
      case 'KEY':
        // vCard 3.0: KEY;TYPE=PGP;ENCODING=b:<base64>
        // vCard 4.0: KEY:data:application/pgp-keys;base64,<base64>  (kept for import compat)
        if (value.startsWith('data:application/pgp-keys;base64,')) {
          fields.pgpKey = value.replace('data:application/pgp-keys;base64,', '').trim();
        } else if (prop.includes('ENCODING=B') || prop.includes('ENCODING=b')) {
          fields.pgpKey = value.trim();
        }
        break;
      case 'SOURCE':
        fields.sourceUrl = value.trim();
        break;
    }
  }

  return fields;
}

// ---------------------------------------------------------------------------
// vCard text-escaping (RFC 6350 §3.4)
// Escapes: , ; \ newline
// ---------------------------------------------------------------------------

function escape(str) {
  return str
    .replace(/\\/g, '\\\\')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,')
    .replace(/\n/g, '\\n');
}

function unescape(str) {
  return str
    .replace(/\\n/gi, '\n')
    .replace(/\\,/g, ',')
    .replace(/\\;/g, ';')
    .replace(/\\\\/g, '\\');
}
