import { describe, expect, it } from 'vitest';
import { invokeWasm, type WasmExports } from '../src/wasm/loader';

describe('WASM loader allocation cleanup', () => {
  it('forwards each allocation length to dealloc across repeated calls', () => {
    const memory = new WebAssembly.Memory({ initial: 1 });
    const deallocated: Array<[number, number]> = [];
    let next = 8;
    const result = new TextEncoder().encode('{"ok":true}');
    new Uint8Array(memory.buffer, 60_000, result.length).set(result);

    const exports = {
      memory,
      alloc(length: number) {
        const ptr = next;
        next += length;
        return ptr;
      },
      dealloc(ptr: number, length: number) {
        deallocated.push([ptr, length]);
      },
      result_ptr: () => 60_000,
      result_len: () => result.length,
      verify_signed_attestation: () => 0,
    } as unknown as WasmExports;

    invokeWasm(exports, 'verify_signed_attestation', [
      { kind: 'bytes', data: new Uint8Array(2) },
      { kind: 'bytes', data: new Uint8Array(3) },
    ]);
    invokeWasm(exports, 'verify_signed_attestation', [
      { kind: 'bytes', data: new Uint8Array(5) },
      { kind: 'bytes', data: new Uint8Array(1) },
    ]);

    expect(deallocated.map(([, length]) => length)).toEqual([2, 3, 5, 1]);
  });
});
