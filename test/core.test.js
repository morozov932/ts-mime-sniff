import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sniffMimeType } from '../src/index.js';

const U8 = (...arr) => new Uint8Array(arr);

test('png magic', () => {
  assert.equal(sniffMimeType(U8(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)), 'image/png');
});

test('jpeg magic', () => {
  assert.equal(sniffMimeType(U8(0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10)), 'image/jpeg');
});

function buildFtyp(major) {
  const b = new Uint8Array(12);
  b[0] = 0x00; b[1] = 0x00; b[2] = 0x00; b[3] = 0x20;
  b[4] = 0x66; b[5] = 0x74; b[6] = 0x79; b[7] = 0x70;
  b[8] = major.charCodeAt(0);
  b[9] = major.charCodeAt(1);
  b[10] = major.charCodeAt(2);
  b[11] = major.charCodeAt(3);
  return b;
}

test('isom/mp4 magic', () => {
  assert.equal(sniffMimeType(buildFtyp('isom')), 'video/mp4');
});

test('unknown data falls back to octet-stream', () => {
  assert.equal(sniffMimeType(U8(0x01, 0x02, 0x03, 0x04)), 'application/octet-stream');
});

test('empty input falls back to octet-stream', () => {
  assert.equal(sniffMimeType(new Uint8Array(0)), 'application/octet-stream');
});

test('partial magic prefix smaller than 12 bytes does not falsely match png', () => {
  assert.equal(sniffMimeType(U8(0x89, 0x50, 0x4e)), 'application/octet-stream');
});

test('non-Uint8Array input throws', () => {
  assert.throws(() => sniffMimeType([0x89, 0x50]), TypeError);
});
