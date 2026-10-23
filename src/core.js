/**
 * Sniff a MIME type from the leading bytes of a byte stream.
 *
 * Why a fixed substring length: the spec's longest magic is 12 bytes (PDF).
 * We copy at most 12 bytes from the input into a pre-allocated
 * Uint8Array so callers can pass a slice of any size and we still
 * compare against a stable, zero-padded buffer.
 *
 * @param {Uint8Array} bytes - A slice of the head of a file.
 * @returns {string} a MIME type string, or 'application/octet-stream' when
 *   no known magic matches.
 */
export function sniffMimeType(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('sniffMimeType expects a Uint8Array');
  }

  const head = new Uint8Array(12);
  const n = Math.min(bytes.length, 12);
  head.set(bytes.subarray(0, n));

  if (hasAsciiAt(head, 0, 0xff) && hasAsciiAt(head, 1, 0xfe)) {
    return 'text/plain';
  }
  if (hasAsciiAt(head, 0, 0xef) && hasAsciiAt(head, 1, 0xbb) && hasAsciiAt(head, 2, 0xbf)) {
    return 'text/plain';
  }
  if (hasAsciiAt(head, 0, 0x3c) && hasAsciiAt(head, 1, 0x21)) {
    return 'text/html';
  }
  if (hasAsciiAt(head, 0, 0x89) && hasAsciiAt(head, 1, 0x50) && hasAsciiAt(head, 2, 0x4e) && hasAsciiAt(head, 3, 0x47)) {
    return 'image/png';
  }
  if (hasAsciiAt(head, 0, 0xff) && hasAsciiAt(head, 1, 0xd8) && hasAsciiAt(head, 2, 0xff)) {
    return 'image/jpeg';
  }
  if (hasAsciiAt(head, 0, 0x47) && hasAsciiAt(head, 1, 0x49) && hasAsciiAt(head, 2, 0x46) && hasAsciiAt(head, 3, 0x38)) {
    return 'image/gif';
  }
  if (hasAsciiAt(head, 0, 0x25) && hasAsciiAt(head, 1, 0x50) && hasAsciiAt(head, 2, 0x44) && hasAsciiAt(head, 3, 0x46)) {
    return 'application/pdf';
  }
  if (hasAsciiAt(head, 4, 0x66) && hasAsciiAt(head, 5, 0x74) && hasAsciiAt(head, 6, 0x79) && hasAsciiAt(head, 7, 0x70)) {
    return 'video/mp4';
  }
  if (hasAsciiAt(head, 0, 0x42) && hasAsciiAt(head, 1, 0x4d)) {
    return 'image/bmp';
  }
  if (hasAsciiAt(head, 0, 0x49) && hasAsciiAt(head, 1, 0x49) && hasAsciiAt(head, 2, 0x2a) && hasAsciiAt(head, 3, 0x00)) {
    return 'image/tiff';
  }
  if (hasAsciiAt(head, 0, 0x4d) && hasAsciiAt(head, 1, 0x4d) && hasAsciiAt(head, 2, 0x00) && hasAsciiAt(head, 3, 0x2a)) {
    return 'image/tiff';
  }
  if (hasAsciiAt(head, 0, 0x52) && hasAsciiAt(head, 1, 0x61) && hasAsciiAt(head, 2, 0x72) && hasAsciiAt(head, 3, 0x21) && hasAsciiAt(head, 4, 0x1a) && hasAsciiAt(head, 5, 0x07)) {
    return 'application/vnd.rar';
  }
  if (hasAsciiAt(head, 0, 0x50) && hasAsciiAt(head, 1, 0x4b) && (hasAsciiAt(head, 2, 0x03) || hasAsciiAt(head, 2, 0x05)) && (hasAsciiAt(head, 3, 0x04) || hasAsciiAt(head, 3, 0x06))) {
    return 'application/zip';
  }
  if (hasAsciiAt(head, 0, 0x1f) && hasAsciiAt(head, 1, 0x8b)) {
    return 'application/gzip';
  }

  return 'application/octet-stream';
}

function hasAsciiAt(buf, offset, expected) {
  return buf[offset] === expected;
}
