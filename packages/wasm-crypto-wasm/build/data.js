// Copyright 2019-2021 @axia-js/wasm-crypto-wasm authors & contributors
// SPDX-License-Identifier: Apache-2.0
import { toByteArray } from "./base64.js";
import { bytes, sizeUncompressed } from "./bytes.js";
import { unzlibSync } from "./fflate.js";
export const wasmBytes = unzlibSync(toByteArray(bytes), new Uint8Array(sizeUncompressed));