// Copyright 2019-2021 @axia-js/wasm authors & contributors
// SPDX-License-Identifier: Apache-2.0

const fflate = require('fflate/node');
const fs = require('fs');
const { formatNumber } = require('@axia-js/util');

const W_NAME = 'wasm-crypto-wasm';

const data = fs.readFileSync('./bytes/wasm_opt.wasm');
const compressed = Buffer.from(fflate.zlibSync(data, { level: 9 }));

console.log(`*** Compressed WASM: ${formatNumber(data.length)} -> ${formatNumber(compressed.length)} (${(100 * compressed.length / data.length).toFixed(2)}%)`);

fs.writeFileSync(`./${W_NAME}/build/cjs/bytes.js`, `// Copyright 2019-2021 @axia-js/${W_NAME} authors & contributors
// SPDX-License-Identifier: Apache-2.0

// Generated as part of the build, do not edit

const sizeCompressed = ${compressed.length};
const sizeUncompressed = ${data.length};
const bytes = '${compressed.toString('base64')}';

module.exports = { bytes, sizeCompressed, sizeUncompressed };
`);
