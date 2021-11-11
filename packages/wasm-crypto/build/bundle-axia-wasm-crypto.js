const axiaWasmCrypto = (function (exports, util) {
  'use strict';

  const global = window;

  // Copyright 2019-2021 @axia-js/wasm-crypto-asmjs authors & contributors
  // SPDX-License-Identifier: Apache-2.0
  const asmJsInit = null;

  // Copyright 2019-2021 @axia-js/wasm-crypto authors & contributors
  // SPDX-License-Identifier: Apache-2.0
  // MIT License
  //
  // Copyright (c) 2014 Jameson Little
  //
  // https://github.com/beatgammit/base64-js/blob/88957c9943c7e2a0f03cdf73e71d579e433627d3/index.js
  // This only contains the toByteArray function (no encoding)
  //
  // Only tweaks make here are some TS adjustments (we use strict null checks), the code is otherwise as-is with
  // only the single required function provided
  const CODE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lookup = [];
  const revLookup = [];

  for (let i = 0; i < CODE.length; ++i) {
    lookup[i] = CODE[i];
    revLookup[CODE.charCodeAt(i)] = i;
  } // Support decoding URL-safe base64 strings, as Node.js does.
  // See: https://en.wikipedia.org/wiki/Base64#URL_applications


  revLookup['-'.charCodeAt(0)] = 62;
  revLookup['_'.charCodeAt(0)] = 63;

  function getLens(b64) {
    const len = b64.length;

    if (len % 4 > 0) {
      throw new Error('Invalid string. Length must be a multiple of 4');
    } // Trim off extra bytes after placeholder bytes are found
    // See: https://github.com/beatgammit/base64-js/issues/42


    const validLen = b64.indexOf('=');
    return validLen === -1 ? [len, 0] : [validLen, 4 - validLen % 4];
  }

  function toByteArray(b64) {
    const [validLen, placeHoldersLen] = getLens(b64);
    const arr = new Uint8Array((validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen);
    let curByte = 0;
    let i;
    let tmp; // if there are placeholders, only get up to the last complete 4 chars

    const len = placeHoldersLen > 0 ? validLen - 4 : validLen;

    for (i = 0; i < len; i += 4) {
      tmp = revLookup[b64.charCodeAt(i)] << 18 | revLookup[b64.charCodeAt(i + 1)] << 12 | revLookup[b64.charCodeAt(i + 2)] << 6 | revLookup[b64.charCodeAt(i + 3)];
      arr[curByte++] = tmp >> 16 & 0xFF;
      arr[curByte++] = tmp >> 8 & 0xFF;
      arr[curByte++] = tmp & 0xFF;
    }

    if (placeHoldersLen === 2) {
      tmp = revLookup[b64.charCodeAt(i)] << 2 | revLookup[b64.charCodeAt(i + 1)] >> 4;
      arr[curByte++] = tmp & 0xFF;
    } else if (placeHoldersLen === 1) {
      tmp = revLookup[b64.charCodeAt(i)] << 10 | revLookup[b64.charCodeAt(i + 1)] << 4 | revLookup[b64.charCodeAt(i + 2)] >> 2;
      arr[curByte++] = tmp >> 8 & 0xFF;
      arr[curByte++] = tmp & 0xFF;
    }

    return arr;
  }

  // Copyright 2019-2021 @axia-js/wasm-crypto-wasm authors & contributors
  // SPDX-License-Identifier: Apache-2.0

  var bytes_1 = '';

  var sizeUncompressed$1 = 0;

  // Copyright 2019-2021 @axia-js/wasm-crypto-wasm authors & contributors
  const bytes = bytes_1;
  const sizeUncompressed = sizeUncompressed$1;

  // Copyright 2019-2021 @axia-js/wasm-crypto authors & contributors
  // SPDX-License-Identifier: Apache-2.0
  // MIT License
  //
  // Copyright (c) 2020 Arjun Barrett
  //
  // Copied from https://github.com/101arrowz/fflate/blob/73c737941ec89d85cdf0ad39ee6f26c5fdc95fd7/src/index.ts
  // This only contains the unzlibSync function, no compression, no async, no workers
  //
  // These 2 issues are addressed as a short-term, stop-gap solution
  //   - https://github.com/axia-js/api/issues/2963
  //   - https://github.com/101arrowz/fflate/issues/17
  //
  // Only tweaks make here are some TS adjustments (we use strict null checks), the code is otherwise as-is with
  // only the single required function provided (compression is still being done in the build with fflate)

  /* eslint-disable */
  // inflate state
  // aliases for shorter compressed code (most minifers don't do this)
  const u8 = Uint8Array,
        u16 = Uint16Array,
        u32 = Uint32Array; // code length index map

  const clim = new u8([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]); // fixed length extra bits

  const fleb = new u8([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
  /* unused */
  0, 0,
  /* impossible */
  0]); // fixed distance extra bits
  // see fleb note

  const fdeb = new u8([0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
  /* unused */
  0, 0]); // get base, reverse index map from extra bits

  const freb = (eb, start) => {
    const b = new u16(31);

    for (let i = 0; i < 31; ++i) {
      b[i] = start += 1 << eb[i - 1];
    } // numbers here are at max 18 bits


    const r = new u32(b[30]);

    for (let i = 1; i < 30; ++i) {
      for (let j = b[i]; j < b[i + 1]; ++j) {
        r[j] = j - b[i] << 5 | i;
      }
    }

    return [b, r];
  };

  const [fl, revfl] = freb(fleb, 2); // we can ignore the fact that the other numbers are wrong; they never happen anyway

  fl[28] = 258, revfl[258] = 28;
  const [fd] = freb(fdeb, 0); // map of value to reverse (assuming 16 bits)

  const rev = new u16(32768);

  for (let i = 0; i < 32768; ++i) {
    // reverse table algorithm from SO
    let x = (i & 0xAAAA) >>> 1 | (i & 0x5555) << 1;
    x = (x & 0xCCCC) >>> 2 | (x & 0x3333) << 2;
    x = (x & 0xF0F0) >>> 4 | (x & 0x0F0F) << 4;
    rev[i] = ((x & 0xFF00) >>> 8 | (x & 0x00FF) << 8) >>> 1;
  } // create huffman tree from u8 "map": index -> code length for code index
  // mb (max bits) must be at most 15
  // TODO: optimize/split up?


  const hMap = (cd, mb, r) => {
    const s = cd.length; // index

    let i = 0; // u16 "map": index -> # of codes with bit length = index

    const l = new u16(mb); // length of cd must be 288 (total # of codes)

    for (; i < s; ++i) ++l[cd[i] - 1]; // u16 "map": index -> minimum code for bit length = index


    const le = new u16(mb);

    for (i = 0; i < mb; ++i) {
      le[i] = le[i - 1] + l[i - 1] << 1;
    }

    let co;

    if (r) {
      // u16 "map": index -> number of actual bits, symbol for code
      co = new u16(1 << mb); // bits to remove for reverser

      const rvb = 15 - mb;

      for (i = 0; i < s; ++i) {
        // ignore 0 lengths
        if (cd[i]) {
          // num encoding both symbol and bits read
          const sv = i << 4 | cd[i]; // free bits

          const r = mb - cd[i]; // start value

          let v = le[cd[i] - 1]++ << r; // m is end value

          for (const m = v | (1 << r) - 1; v <= m; ++v) {
            // every 16 bit value starting with the code yields the same result
            co[rev[v] >>> rvb] = sv;
          }
        }
      }
    } else {
      co = new u16(s);

      for (i = 0; i < s; ++i) co[i] = rev[le[cd[i] - 1]++] >>> 15 - cd[i];
    }

    return co;
  }; // fixed length tree


  const flt = new u8(288);

  for (let i = 0; i < 144; ++i) flt[i] = 8;

  for (let i = 144; i < 256; ++i) flt[i] = 9;

  for (let i = 256; i < 280; ++i) flt[i] = 7;

  for (let i = 280; i < 288; ++i) flt[i] = 8; // fixed distance tree


  const fdt = new u8(32);

  for (let i = 0; i < 32; ++i) fdt[i] = 5; // fixed length map


  const flrm = hMap(flt, 9, 1); // fixed distance map

  const fdrm = hMap(fdt, 5, 1); // read d, starting at bit p and mask with m

  const bits = (d, p, m) => {
    const o = p >>> 3;
    return (d[o] | d[o + 1] << 8) >>> (p & 7) & m;
  }; // read d, starting at bit p continuing for at least 16 bits


  const bits16 = (d, p) => {
    const o = p >>> 3;
    return (d[o] | d[o + 1] << 8 | d[o + 2] << 16) >>> (p & 7);
  }; // get end of byte


  const shft = p => (p >>> 3) + (p & 7 && 1); // typed array slice - allows garbage collector to free original reference,
  // while being more compatible than .slice


  const slc = (v, s, e) => {
    if (s == null || s < 0) s = 0;
    if (e == null || e > v.length) e = v.length; // can't use .constructor in case user-supplied

    const n = new (v instanceof u16 ? u16 : v instanceof u32 ? u32 : u8)(e - s);
    n.set(v.subarray(s, e));
    return n;
  }; // find max of array


  const max = a => {
    let m = a[0];

    for (let i = 1; i < a.length; ++i) {
      if (a[i] > m) m = a[i];
    }

    return m;
  }; // expands raw DEFLATE data


  const inflt = (dat, buf, st) => {
    const noSt = !st || st.i;
    if (!st) st = {}; // source length

    const sl = dat.length; // have to estimate size

    const noBuf = !buf || !noSt; // Assumes roughly 33% compression ratio average

    if (!buf) buf = new u8(sl * 3); // ensure buffer can fit at least l elements

    const cbuf = l => {
      let bl = buf.length; // need to increase size to fit

      if (l > bl) {
        // Double or set to necessary, whichever is greater
        const nbuf = new u8(Math.max(bl << 1, l));
        nbuf.set(buf);
        buf = nbuf;
      }
    }; //  last chunk         bitpos           bytes


    let final = st.f || 0,
        pos = st.p || 0,
        bt = st.b || 0,
        lm = st.l,
        dm = st.d,
        lbt = st.m,
        dbt = st.n;
    if (final && !lm) return buf; // total bits

    const tbts = sl << 3;

    do {
      if (!lm) {
        // BFINAL - this is only 1 when last chunk is next
        st.f = final = bits(dat, pos, 1); // type: 0 = no compression, 1 = fixed huffman, 2 = dynamic huffman

        const type = bits(dat, pos + 1, 3);
        pos += 3;

        if (!type) {
          // go to end of byte boundary
          const s = shft(pos) + 4,
                l = dat[s - 4] | dat[s - 3] << 8,
                t = s + l;

          if (t > sl) {
            if (noSt) throw 'unexpected EOF';
            break;
          } // ensure size


          if (noBuf) cbuf(bt + l); // Copy over uncompressed data

          buf.set(dat.subarray(s, t), bt); // Get new bitpos, update byte count

          st.b = bt += l, st.p = pos = t << 3;
          continue;
        } else if (type == 1) lm = flrm, dm = fdrm, lbt = 9, dbt = 5;else if (type == 2) {
          //  literal                            lengths
          const hLit = bits(dat, pos, 31) + 257,
                hcLen = bits(dat, pos + 10, 15) + 4;
          const tl = hLit + bits(dat, pos + 5, 31) + 1;
          pos += 14; // length+distance tree

          const ldt = new u8(tl); // code length tree

          const clt = new u8(19);

          for (let i = 0; i < hcLen; ++i) {
            // use index map to get real code
            clt[clim[i]] = bits(dat, pos + i * 3, 7);
          }

          pos += hcLen * 3; // code lengths bits

          const clb = max(clt),
                clbmsk = (1 << clb) - 1;
          if (!noSt && pos + tl * (clb + 7) > tbts) break; // code lengths map

          const clm = hMap(clt, clb, 1);

          for (let i = 0; i < tl;) {
            const r = clm[bits(dat, pos, clbmsk)]; // bits read

            pos += r & 15; // symbol

            const s = r >>> 4; // code length to copy

            if (s < 16) {
              ldt[i++] = s;
            } else {
              //  copy   count
              let c = 0,
                  n = 0;
              if (s == 16) n = 3 + bits(dat, pos, 3), pos += 2, c = ldt[i - 1];else if (s == 17) n = 3 + bits(dat, pos, 7), pos += 3;else if (s == 18) n = 11 + bits(dat, pos, 127), pos += 7;

              while (n--) ldt[i++] = c;
            }
          } //    length tree                 distance tree


          const lt = ldt.subarray(0, hLit),
                dt = ldt.subarray(hLit); // max length bits

          lbt = max(lt); // max dist bits

          dbt = max(dt);
          lm = hMap(lt, lbt, 1);
          dm = hMap(dt, dbt, 1);
        } else throw 'invalid block type';

        if (pos > tbts) throw 'unexpected EOF';
      } // Make sure the buffer can hold this + the largest possible addition
      // maximum chunk size (practically, theoretically infinite) is 2^17;


      if (noBuf) cbuf(bt + 131072);
      const lms = (1 << lbt) - 1,
            dms = (1 << dbt) - 1;
      const mxa = lbt + dbt + 18;

      while (noSt || pos + mxa < tbts) {
        // bits read, code
        const c = lm[bits16(dat, pos) & lms],
              sym = c >>> 4;
        pos += c & 15;
        if (pos > tbts) throw 'unexpected EOF';
        if (!c) throw 'invalid length/literal';
        if (sym < 256) buf[bt++] = sym;else if (sym == 256) {
          lm = undefined;
          break;
        } else {
          let add = sym - 254; // no extra bits needed if less

          if (sym > 264) {
            // index
            const i = sym - 257,
                  b = fleb[i];
            add = bits(dat, pos, (1 << b) - 1) + fl[i];
            pos += b;
          } // dist


          const d = dm[bits16(dat, pos) & dms],
                dsym = d >>> 4;
          if (!d) throw 'invalid distance';
          pos += d & 15;
          let dt = fd[dsym];

          if (dsym > 3) {
            const b = fdeb[dsym];
            dt += bits16(dat, pos) & (1 << b) - 1, pos += b;
          }

          if (pos > tbts) throw 'unexpected EOF';
          if (noBuf) cbuf(bt + 131072);
          const end = bt + add;

          for (; bt < end; bt += 4) {
            buf[bt] = buf[bt - dt];
            buf[bt + 1] = buf[bt + 1 - dt];
            buf[bt + 2] = buf[bt + 2 - dt];
            buf[bt + 3] = buf[bt + 3 - dt];
          }

          bt = end;
        }
      }

      st.l = lm, st.p = pos, st.b = bt;
      if (lm) final = 1, st.m = lbt, st.d = dm, st.n = dbt;
    } while (!final);

    return bt == buf.length ? buf : slc(buf, 0, bt);
  }; // zlib valid


  const zlv = d => {
    if ((d[0] & 15) != 8 || d[0] >>> 4 > 7 || (d[0] << 8 | d[1]) % 31) throw 'invalid zlib data';
    if (d[1] & 32) throw 'invalid zlib data: preset dictionaries not supported';
  };
  /**
   * Expands Zlib data
   * @param data The data to decompress
   * @param out Where to write the data. Saves memory if you know the decompressed size and provide an output buffer of that length.
   * @returns The decompressed version of the data
   */


  function unzlibSync(data, out) {
    return inflt((zlv(data), data.subarray(2, -4)), out);
  }

  // Copyright 2019-2021 @axia-js/wasm-crypto-wasm authors & contributors
  const wasmBytes = unzlibSync(toByteArray(bytes), new Uint8Array(sizeUncompressed));

  // Copyright 2019-2021 @axia-js/wasm-crypto authors & contributors
  let wasm = null;
  let cachegetInt32 = null;
  let cachegetUint8 = null;
  async function initWasm(wasmBytes, asmFn, wbg) {
    try {
      util.assert(typeof WebAssembly !== 'undefined' && wasmBytes && wasmBytes.length, 'WebAssembly is not available in your environment');
      const source = await WebAssembly.instantiate(wasmBytes, {
        wbg
      });
      wasm = source.instance.exports;
    } catch (error) {
      // if we have a valid supplied asm.js, return that
      if (asmFn) {
        wasm = asmFn(wbg);
      } else {
        console.error('FATAL: Unable to initialize @axia-js/wasm-crypto');
        console.error(error);
        wasm = null;
      }
    }
  } // FIXME We really would love to clean this up and have a sign like (wasm, ...params) => T
  // Alas, TypeScript foo is not that great today, so we sadly have an extra closure here

  function withWasm(fn) {
    return (...params) => {
      util.assert(wasm, 'The WASM interface has not been initialized. Ensure that you wait for the initialization Promise with waitReady() from @axia-js/wasm-crypto (or cryptoWaitReady() from @axia-js/util-crypto) before attempting to use WASM-only interfaces.');
      return fn(wasm)(...params);
    };
  }
  function getWasm() {
    return wasm;
  }
  function getInt32() {
    if (cachegetInt32 === null || cachegetInt32.buffer !== wasm.memory.buffer) {
      cachegetInt32 = new Int32Array(wasm.memory.buffer);
    }

    return cachegetInt32;
  }
  function getUint8() {
    if (cachegetUint8 === null || cachegetUint8.buffer !== wasm.memory.buffer) {
      cachegetUint8 = new Uint8Array(wasm.memory.buffer);
    }

    return cachegetUint8;
  }
  function getU8a(ptr, len) {
    return getUint8().subarray(ptr / 1, ptr / 1 + len);
  }
  function getString(ptr, len) {
    return util.u8aToString(getU8a(ptr, len));
  }
  function allocU8a(arg) {
    const ptr = wasm.__wbindgen_malloc(arg.length * 1);

    getUint8().set(arg, ptr / 1);
    return [ptr, arg.length];
  }
  function allocString(arg) {
    return allocU8a(util.stringToU8a(arg));
  }
  function resultU8a() {
    const r0 = getInt32()[8 / 4 + 0];
    const r1 = getInt32()[8 / 4 + 1];
    const ret = getU8a(r0, r1).slice();

    wasm.__wbindgen_free(r0, r1 * 1);

    return ret;
  }
  function resultString() {
    return util.u8aToString(resultU8a());
  }

  // Copyright 2017-2021 @axia-js/x-randomvalues authors & contributors
  function getRandomValues(arr) {
    return crypto.getRandomValues(arr);
  }

  // Copyright 2019-2021 @axia-js/wasm-crypto authors & contributors
  const DEFAULT_CRYPTO = {
    getRandomValues
  };
  const DEFAULT_SELF = {
    crypto: DEFAULT_CRYPTO
  };
  const heap = new Array(32).fill(undefined).concat(undefined, null, true, false);
  let heapNext = heap.length;

  function getObject(idx) {
    return heap[idx];
  }

  function dropObject(idx) {
    if (idx < 36) {
      return;
    }

    heap[idx] = heapNext;
    heapNext = idx;
  }

  function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
  }

  function addObject(obj) {
    if (heapNext === heap.length) {
      heap.push(heap.length + 1);
    }

    const idx = heapNext;
    heapNext = heap[idx];
    heap[idx] = obj;
    return idx;
  }

  function __wbindgen_is_undefined(idx) {
    return getObject(idx) === undefined;
  }
  function __wbg_self_1b7a39e3a92c949c() {
    return addObject(DEFAULT_SELF);
  }
  function __wbg_require_604837428532a733(ptr, len) {
    throw new Error(`Unable to require ${getString(ptr, len)}`);
  } // eslint-disable-next-line @typescript-eslint/no-unused-vars

  function __wbg_crypto_968f1772287e2df0(_idx) {
    return addObject(DEFAULT_CRYPTO);
  } // eslint-disable-next-line @typescript-eslint/no-unused-vars

  function __wbg_getRandomValues_a3d34b4fee3c2869(_idx) {
    return addObject(DEFAULT_CRYPTO.getRandomValues);
  } // eslint-disable-next-line @typescript-eslint/no-unused-vars

  function __wbg_getRandomValues_f5e14ab7ac8e995d(_arg0, ptr, len) {
    DEFAULT_CRYPTO.getRandomValues(getU8a(ptr, len));
  } // eslint-disable-next-line @typescript-eslint/no-unused-vars

  function __wbg_randomFillSync_d5bd2d655fdf256a(_idx, _ptr, _len) {
    throw new Error('randomFillsync is not available'); // getObject(idx).randomFillSync(getU8a(ptr, len));
  }
  function __wbindgen_object_drop_ref(idx) {
    takeObject(idx);
  }
  function abort() {
    throw new Error('abort');
  }

  const imports = /*#__PURE__*/Object.freeze({
    __proto__: null,
    __wbindgen_is_undefined: __wbindgen_is_undefined,
    __wbg_self_1b7a39e3a92c949c: __wbg_self_1b7a39e3a92c949c,
    __wbg_require_604837428532a733: __wbg_require_604837428532a733,
    __wbg_crypto_968f1772287e2df0: __wbg_crypto_968f1772287e2df0,
    __wbg_getRandomValues_a3d34b4fee3c2869: __wbg_getRandomValues_a3d34b4fee3c2869,
    __wbg_getRandomValues_f5e14ab7ac8e995d: __wbg_getRandomValues_f5e14ab7ac8e995d,
    __wbg_randomFillSync_d5bd2d655fdf256a: __wbg_randomFillSync_d5bd2d655fdf256a,
    __wbindgen_object_drop_ref: __wbindgen_object_drop_ref,
    abort: abort
  });

  // Copyright 2017-2021 @axia-js/wasm-crypto authors & contributors
  // SPDX-License-Identifier: Apache-2.0
  // Auto-generated by @axia-js/dev, do not edit
  const packageInfo = {
    name: '@axia-js/wasm-crypto',
    version: '1.1.0'
  };

  // Copyright 2019-2021 @axia-js/wasm-crypto authors & contributors
  const wasmPromise = initWasm(wasmBytes, asmJsInit, imports).catch(() => null);
  const bip39Generate = withWasm(wasm => words => {
    wasm.ext_bip39_generate(8, words);
    return resultString();
  });
  const bip39ToEntropy = withWasm(wasm => phrase => {
    const [ptr0, len0] = allocString(phrase);
    wasm.ext_bip39_to_entropy(8, ptr0, len0);
    return resultU8a();
  });
  const bip39ToMiniSecret = withWasm(wasm => (phrase, password) => {
    const [ptr0, len0] = allocString(phrase);
    const [ptr1, len1] = allocString(password);
    wasm.ext_bip39_to_mini_secret(8, ptr0, len0, ptr1, len1);
    return resultU8a();
  });
  const bip39ToSeed = withWasm(wasm => (phrase, password) => {
    const [ptr0, len0] = allocString(phrase);
    const [ptr1, len1] = allocString(password);
    wasm.ext_bip39_to_seed(8, ptr0, len0, ptr1, len1);
    return resultU8a();
  });
  const bip39Validate = withWasm(wasm => phrase => {
    const [ptr0, len0] = allocString(phrase);
    const ret = wasm.ext_bip39_validate(ptr0, len0);
    return ret !== 0;
  });
  const ed25519KeypairFromSeed = withWasm(wasm => seed => {
    const [ptr0, len0] = allocU8a(seed);
    wasm.ext_ed_from_seed(8, ptr0, len0);
    return resultU8a();
  });
  const ed25519Sign = withWasm(wasm => (pubkey, seckey, message) => {
    const [ptr0, len0] = allocU8a(pubkey);
    const [ptr1, len1] = allocU8a(seckey);
    const [ptr2, len2] = allocU8a(message);
    wasm.ext_ed_sign(8, ptr0, len0, ptr1, len1, ptr2, len2);
    return resultU8a();
  });
  const ed25519Verify = withWasm(wasm => (signature, message, pubkey) => {
    const [ptr0, len0] = allocU8a(signature);
    const [ptr1, len1] = allocU8a(message);
    const [ptr2, len2] = allocU8a(pubkey);
    const ret = wasm.ext_ed_verify(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
  });
  const sr25519DeriveKeypairHard = withWasm(wasm => (pair, cc) => {
    const [ptr0, len0] = allocU8a(pair);
    const [ptr1, len1] = allocU8a(cc);
    wasm.ext_sr_derive_keypair_hard(8, ptr0, len0, ptr1, len1);
    return resultU8a();
  });
  const sr25519DeriveKeypairSoft = withWasm(wasm => (pair, cc) => {
    const [ptr0, len0] = allocU8a(pair);
    const [ptr1, len1] = allocU8a(cc);
    wasm.ext_sr_derive_keypair_soft(8, ptr0, len0, ptr1, len1);
    return resultU8a();
  });
  const sr25519DerivePublicSoft = withWasm(wasm => (pubkey, cc) => {
    const [ptr0, len0] = allocU8a(pubkey);
    const [ptr1, len1] = allocU8a(cc);
    wasm.ext_sr_derive_public_soft(8, ptr0, len0, ptr1, len1);
    return resultU8a();
  });
  const sr25519KeypairFromSeed = withWasm(wasm => seed => {
    const [ptr0, len0] = allocU8a(seed);
    wasm.ext_sr_from_seed(8, ptr0, len0);
    return resultU8a();
  });
  const sr25519Sign = withWasm(wasm => (pubkey, secret, message) => {
    const [ptr0, len0] = allocU8a(pubkey);
    const [ptr1, len1] = allocU8a(secret);
    const [ptr2, len2] = allocU8a(message);
    wasm.ext_sr_sign(8, ptr0, len0, ptr1, len1, ptr2, len2);
    return resultU8a();
  });
  const sr25519Verify = withWasm(wasm => (signature, message, pubkey) => {
    const [ptr0, len0] = allocU8a(signature);
    const [ptr1, len1] = allocU8a(message);
    const [ptr2, len2] = allocU8a(pubkey);
    const ret = wasm.ext_sr_verify(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
  });
  const sr25519Agree = withWasm(wasm => (pubkey, secret) => {
    const [ptr0, len0] = allocU8a(pubkey);
    const [ptr1, len1] = allocU8a(secret);
    wasm.ext_sr_agree(8, ptr0, len0, ptr1, len1);
    return resultU8a();
  });
  const vrfSign = withWasm(wasm => (secret, context, message, extra) => {
    const [ptr0, len0] = allocU8a(secret);
    const [ptr1, len1] = allocU8a(context);
    const [ptr2, len2] = allocU8a(message);
    const [ptr3, len3] = allocU8a(extra);
    wasm.ext_vrf_sign(8, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return resultU8a();
  });
  const vrfVerify = withWasm(wasm => (pubkey, context, message, extra, outAndProof) => {
    const [ptr0, len0] = allocU8a(pubkey);
    const [ptr1, len1] = allocU8a(context);
    const [ptr2, len2] = allocU8a(message);
    const [ptr3, len3] = allocU8a(extra);
    const [ptr4, len4] = allocU8a(outAndProof);
    const ret = wasm.ext_vrf_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    return ret !== 0;
  });
  const blake2b = withWasm(wasm => (data, key, size) => {
    const [ptr0, len0] = allocU8a(data);
    const [ptr1, len1] = allocU8a(key);
    wasm.ext_blake2b(8, ptr0, len0, ptr1, len1, size);
    return resultU8a();
  });
  const keccak256 = withWasm(wasm => data => {
    const [ptr0, len0] = allocU8a(data);
    wasm.ext_keccak256(8, ptr0, len0);
    return resultU8a();
  });
  const pbkdf2 = withWasm(wasm => (data, salt, rounds) => {
    const [ptr0, len0] = allocU8a(data);
    const [ptr1, len1] = allocU8a(salt);
    wasm.ext_pbkdf2(8, ptr0, len0, ptr1, len1, rounds);
    return resultU8a();
  });
  const scrypt = withWasm(wasm => (password, salt, log2n, r, p) => {
    const [ptr0, len0] = allocU8a(password);
    const [ptr1, len1] = allocU8a(salt);
    wasm.ext_scrypt(8, ptr0, len0, ptr1, len1, log2n, r, p);
    return resultU8a();
  });
  const sha512 = withWasm(wasm => data => {
    const [ptr0, len0] = allocU8a(data);
    wasm.ext_sha512(8, ptr0, len0);
    return resultU8a();
  });
  const twox = withWasm(wasm => (data, rounds) => {
    const [ptr0, len0] = allocU8a(data);
    wasm.ext_twox(8, ptr0, len0, rounds);
    return resultU8a();
  });
  function isReady() {
    return !!getWasm();
  }
  function waitReady() {
    return wasmPromise.then(() => isReady());
  }

  exports.bip39Generate = bip39Generate;
  exports.bip39ToEntropy = bip39ToEntropy;
  exports.bip39ToMiniSecret = bip39ToMiniSecret;
  exports.bip39ToSeed = bip39ToSeed;
  exports.bip39Validate = bip39Validate;
  exports.blake2b = blake2b;
  exports.ed25519KeypairFromSeed = ed25519KeypairFromSeed;
  exports.ed25519Sign = ed25519Sign;
  exports.ed25519Verify = ed25519Verify;
  exports.isReady = isReady;
  exports.keccak256 = keccak256;
  exports.packageInfo = packageInfo;
  exports.pbkdf2 = pbkdf2;
  exports.scrypt = scrypt;
  exports.sha512 = sha512;
  exports.sr25519Agree = sr25519Agree;
  exports.sr25519DeriveKeypairHard = sr25519DeriveKeypairHard;
  exports.sr25519DeriveKeypairSoft = sr25519DeriveKeypairSoft;
  exports.sr25519DerivePublicSoft = sr25519DerivePublicSoft;
  exports.sr25519KeypairFromSeed = sr25519KeypairFromSeed;
  exports.sr25519Sign = sr25519Sign;
  exports.sr25519Verify = sr25519Verify;
  exports.twox = twox;
  exports.vrfSign = vrfSign;
  exports.vrfVerify = vrfVerify;
  exports.waitReady = waitReady;

  Object.defineProperty(exports, '__esModule', { value: true });

  return exports;

}({}, axiaUtil));
