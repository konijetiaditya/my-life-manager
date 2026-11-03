import { describe, expect, it } from 'vitest';
import { sanitizeFileName, sniff, validateUpload, MAX_FILE_BYTES } from '../src/security/files';
import { parseState } from '../src/security/schema';

const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a]);
const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0]);
const jpg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0]);

describe('file validation', () => {
  it('recognises real types by content', () => {
    expect(sniff(pdf)).toBe('pdf');
    expect(sniff(png)).toBe('png');
    expect(sniff(jpg)).toBe('jpg');
    expect(sniff(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))).toBeNull();
  });
  it('accepts good files', () => {
    expect(validateUpload('Passport scan.pdf', pdf)).toMatchObject({ ok: true, kind: 'pdf' });
    expect(validateUpload('photo.JPEG', jpg)).toMatchObject({ ok: true, kind: 'jpg' });
  });
  it('rejects a disguised file (exe renamed to pdf)', () => {
    const exe = new Uint8Array([0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0]);
    expect(validateUpload('invoice.pdf', exe).ok).toBe(false);
  });
  it('rejects mismatch between name and content', () => {
    expect(validateUpload('scan.png', pdf).ok).toBe(false);
  });
  it('rejects empty and oversized files', () => {
    expect(validateUpload('a.pdf', new Uint8Array(0)).ok).toBe(false);
    const big = new Uint8Array(MAX_FILE_BYTES + 1);
    big.set(pdf);
    expect(validateUpload('a.pdf', big).ok).toBe(false);
  });
  it('rejects dangerous or odd names', () => {
    for (const n of ['../../etc/passwd.pdf', 'a/b.pdf', 'a\\b.pdf', '..pdf', '.hidden.pdf', 'x\u0000.pdf', '<script>.pdf', 'a'.repeat(120) + '.pdf', '']) {
      expect(sanitizeFileName(n), n).toBeNull();
    }
    expect(sanitizeFileName("Rahul's file (1).pdf")).toBe("Rahul's file (1).pdf");
  });
  it('respects the allowed list', () => {
    expect(validateUpload('a.pdf', pdf, ['png', 'jpg']).ok).toBe(false);
  });
});

describe('restored data cleaning', () => {
  it('fills in missing sections', () => {
    const s = parseState('{"bills":[{"id":"a"}]}');
    expect(s.ins).toEqual([]);
    expect(Array.isArray(s.activity)).toBe(true);
  });
  it('strips prototype-pollution keys', () => {
    const s = parseState('{"bills":[{"id":"a","__proto__":{"polluted":true},"constructor":{"x":1}}],"settings":{}}');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.keys((s.bills as object[])[0] as object)).toEqual(['id']);
  });
  it('rejects non-objects, bad sections and records without ids', () => {
    expect(() => parseState('[]')).toThrow();
    expect(() => parseState('not json')).toThrow();
    expect(() => parseState('{"bills":"x"}')).toThrow();
    expect(() => parseState('{"bills":[{"name":"no id"}]}')).toThrow();
  });
  it('truncates huge strings and refuses deep nesting', () => {
    const s = parseState(JSON.stringify({ bills: [{ id: 'a', notes: 'x'.repeat(20000) }] }));
    expect(((s.bills as Array<{ notes: string }>)[0]!.notes).length).toBe(5000);
    let deep: unknown = 1;
    for (let i = 0; i < 20; i++) deep = { d: deep };
    expect(() => parseState(JSON.stringify({ bills: [{ id: 'a', deep }] }))).toThrow();
  });
});
