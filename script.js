/**
 * UUID & Hash Generator - Client-Side Security Engine
 * Author: bordia98
 * 100% Client-Side - Zero Tracking - Zero Data Sent
 */

// ----------------------------------------------------------------------------
// Pure JavaScript MD5 Implementation (RFC 1321)
// ----------------------------------------------------------------------------
function md5(string) {
  function rotateLeft(lValue, iShiftBits) {
    return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
  }
  function addUnsigned(lX, lY) {
    const lX4 = lX & 0x40000000;
    const lY4 = lY & 0x40000000;
    const lX8 = lX & 0x80000000;
    const lY8 = lY & 0x80000000;
    const lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
    if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
      else return lResult ^ 0x40000000 ^ lX8 ^ lY8;
    } else {
      return lResult ^ lX8 ^ lY8;
    }
  }
  function F(x, y, z) { return (x & y) | ((~x) & z); }
  function G(x, y, z) { return (x & z) | (y & (~z)); }
  function H(x, y, z) { return x ^ y ^ z; }
  function I(x, y, z) { return y ^ (x | (~z)); }

  function FF(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function GG(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function HH(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function II(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }

  function convertToWordArray(str) {
    let lWordCount;
    const lMessageLength = str.length;
    const lNumberOfWords_temp1 = lMessageLength + 8;
    const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    const lWordArray = new Array(lNumberOfWords - 1);
    let lBytePosition = 0;
    let lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (str.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }

  function wordToHex(lValue) {
    let WordToHexValue = '', WordToHexValue_temp = '', lByte, lCount;
    for (lCount = 0; lCount <= 3; lCount++) {
      lByte = (lValue >>> (lCount * 8)) & 255;
      WordToHexValue_temp = '0' + lByte.toString(16);
      WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
    }
    return WordToHexValue;
  }

  function utf8Encode(string) {
    string = string.replace(/\r\n/g, '\n');
    let utftext = '';
    for (let n = 0; n < string.length; n++) {
      const c = string.charCodeAt(n);
      if (c < 128) {
        utftext += String.fromCharCode(c);
      } else if (c > 127 && c < 2048) {
        utftext += String.fromCharCode((c >> 6) | 192);
        utftext += String.fromCharCode((c & 63) | 128);
      } else {
        utftext += String.fromCharCode((c >> 12) | 224);
        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
        utftext += String.fromCharCode((c & 63) | 128);
      }
    }
    return utftext;
  }

  const x = convertToWordArray(utf8Encode(string));
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

  const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
  const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
  const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
  const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

  for (let k = 0; k < x.length; k += 16) {
    const AA = a, BB = b, CC = c, DD = d;
    a = FF(a, b, c, d, x[k + 0], S11, 0xd76aa478);
    d = FF(d, a, b, c, x[k + 1], S12, 0xe8c7b756);
    c = FF(c, d, a, b, x[k + 2], S13, 0x242070db);
    b = FF(b, c, d, a, x[k + 3], S14, 0xc1bdceee);
    a = FF(a, b, c, d, x[k + 4], S11, 0xf57c0faf);
    d = FF(d, a, b, c, x[k + 5], S12, 0x4787c62a);
    c = FF(c, d, a, b, x[k + 6], S13, 0xa8304613);
    b = FF(b, c, d, a, x[k + 7], S14, 0xfd469501);
    a = FF(a, b, c, d, x[k + 8], S11, 0x698098d8);
    d = FF(d, a, b, c, x[k + 9], S12, 0x8b44f7af);
    c = FF(c, d, a, b, x[k + 10], S13, 0xffff5bb1);
    b = FF(b, c, d, a, x[k + 11], S14, 0x895cd7be);
    a = FF(a, b, c, d, x[k + 12], S11, 0x6b901122);
    d = FF(d, a, b, c, x[k + 13], S12, 0xfd987193);
    c = FF(c, d, a, b, x[k + 14], S13, 0xa679438e);
    b = FF(b, c, d, a, x[k + 15], S14, 0x49b40821);

    a = GG(a, b, c, d, x[k + 1], S21, 0xf61e2562);
    d = GG(d, a, b, c, x[k + 6], S22, 0xc040b340);
    c = GG(c, d, a, b, x[k + 11], S23, 0x265e5a51);
    b = GG(b, c, d, a, x[k + 0], S24, 0xe9b6c7aa);
    a = GG(a, b, c, d, x[k + 5], S21, 0xd62f105d);
    d = GG(d, a, b, c, x[k + 10], S22, 0x02441453);
    c = GG(c, d, a, b, x[k + 15], S23, 0xd8a1e681);
    b = GG(b, c, d, a, x[k + 4], S24, 0xe7d3fbc8);
    a = GG(a, b, c, d, x[k + 9], S21, 0x21e1cde6);
    d = GG(d, a, b, c, x[k + 14], S22, 0xc33707d6);
    c = GG(c, d, a, b, x[k + 3], S23, 0xf4d50d87);
    b = GG(b, c, d, a, x[k + 8], S24, 0x455a14ed);
    a = GG(a, b, c, d, x[k + 13], S21, 0xa9e3e905);
    d = GG(d, a, b, c, x[k + 2], S22, 0xfcefa3f8);
    c = GG(c, d, a, b, x[k + 7], S23, 0x676f02d9);
    b = GG(b, c, d, a, x[k + 12], S24, 0x8d2a4c8a);

    a = HH(a, b, c, d, x[k + 5], S31, 0xfffa3942);
    d = HH(d, a, b, c, x[k + 8], S32, 0x8771f681);
    c = HH(c, d, a, b, x[k + 11], S33, 0x6d9d6122);
    b = HH(b, c, d, a, x[k + 14], S34, 0xfde5380c);
    a = HH(a, b, c, d, x[k + 1], S31, 0xa4beea44);
    d = HH(d, a, b, c, x[k + 4], S32, 0x4bdecfa9);
    c = HH(c, d, a, b, x[k + 7], S33, 0xf6bb4b60);
    b = HH(b, c, d, a, x[k + 10], S34, 0xbebfbc70);
    a = HH(a, b, c, d, x[k + 13], S31, 0x289b7ec6);
    d = HH(d, a, b, c, x[k + 0], S32, 0xeaa127fa);
    c = HH(c, d, a, b, x[k + 3], S33, 0xd4ef3085);
    b = HH(b, c, d, a, x[k + 6], S34, 0x04881d05);
    a = HH(a, b, c, d, x[k + 9], S31, 0xd9d4d039);
    d = HH(d, a, b, c, x[k + 12], S32, 0xe6db99e5);
    c = HH(c, d, a, b, x[k + 15], S33, 0x1fa27cf8);
    b = HH(b, c, d, a, x[k + 2], S34, 0xc4ac5665);

    a = II(a, b, c, d, x[k + 0], S41, 0xf4292244);
    d = II(d, a, b, c, x[k + 7], S42, 0x432aff97);
    c = II(c, d, a, b, x[k + 14], S43, 0xab9423a7);
    b = II(b, c, d, a, x[k + 5], S44, 0xfc93a039);
    a = II(a, b, c, d, x[k + 12], S41, 0x655b59c3);
    d = II(d, a, b, c, x[k + 3], S42, 0x8f0ccc92);
    c = II(c, d, a, b, x[k + 10], S43, 0xffeff47d);
    b = II(b, c, d, a, x[k + 1], S44, 0x85845dd1);
    a = II(a, b, c, d, x[k + 8], S41, 0x6fa87e4f);
    d = II(d, a, b, c, x[k + 15], S42, 0xfe2ce6e0);
    c = II(c, d, a, b, x[k + 6], S43, 0xa3014314);
    b = II(b, c, d, a, x[k + 13], S44, 0x4e0811a1);
    a = II(a, b, c, d, x[k + 4], S41, 0xf7537e82);
    d = II(d, a, b, c, x[k + 11], S42, 0xbd3af235);
    c = II(c, d, a, b, x[k + 2], S43, 0x2ad7d2bb);
    b = II(b, c, d, a, x[k + 9], S44, 0xeb86d391);

    a = addUnsigned(a, AA);
    b = addUnsigned(b, BB);
    c = addUnsigned(c, CC);
    d = addUnsigned(d, DD);
  }

  return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

// ----------------------------------------------------------------------------
// MD5 for ArrayBuffer (file hashing)
// ----------------------------------------------------------------------------
function md5ArrayBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return md5(binary);
}

// ----------------------------------------------------------------------------
// Main Application
// ----------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // 1. Theme Management (Default Light)
  const themeToggle = document.getElementById('themeToggle');
  const root = document.documentElement;

  const savedTheme = localStorage.getItem('theme') || 'light';
  root.setAttribute('data-theme', savedTheme);

  themeToggle.addEventListener('click', () => {
    const currentTheme = root.getAttribute('data-theme') || 'light';
    const nextTheme = currentTheme === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', nextTheme);
    localStorage.setItem('theme', nextTheme);
    showToast(`Switched to ${nextTheme} theme`);
  });

  // 2. Toast System
  const toastEl = document.getElementById('toast');
  let toastTimer = null;

  function showToast(message) {
    if (!toastEl) return;
    toastEl.textContent = message;
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastEl.classList.remove('show');
    }, 2200);
  }

  // 3. Tab Switching
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const targetPanel = document.getElementById(`tab-${btn.dataset.tab}`);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }
    });
  });

  // --------------------------------------------------------------------------
  // 4. UUID Generator
  // --------------------------------------------------------------------------
  const generateUuidBtn = document.getElementById('generateUuidBtn');
  const uuidCount = document.getElementById('uuidCount');
  const optNoHyphens = document.getElementById('optNoHyphens');
  const optUppercase = document.getElementById('optUppercase');
  const optBraces = document.getElementById('optBraces');

  const uuidSingleContainer = document.getElementById('uuidSingleContainer');
  const primaryUuidDisplay = document.getElementById('primaryUuidDisplay');
  const copySingleUuidBtn = document.getElementById('copySingleUuidBtn');

  const uuidMultiContainer = document.getElementById('uuidMultiContainer');
  const uuidResultsTextarea = document.getElementById('uuidResultsTextarea');
  const copyAllUuidBtn = document.getElementById('copyAllUuidBtn');
  const downloadUuidBtn = document.getElementById('downloadUuidBtn');

  // RFC 9562 UUID v7 implementation
  function generateUuidV7() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);

    const now = Date.now();
    // 48-bit timestamp in big-endian
    bytes[0] = (now / 0x10000000000) & 0xff;
    bytes[1] = (now / 0x100000000) & 0xff;
    bytes[2] = (now / 0x1000000) & 0xff;
    bytes[3] = (now / 0x10000) & 0xff;
    bytes[4] = (now / 0x100) & 0xff;
    bytes[5] = now & 0xff;

    // version 7 (0111)
    bytes[6] = 0x70 | (bytes[6] & 0x0f);
    // variant 1 (10xx)
    bytes[8] = 0x80 | (bytes[8] & 0x3f);

    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function generateSingleUuid(version) {
    let u = '';
    if (version === 'v7') {
      u = generateUuidV7();
    } else {
      // v4 standard
      u = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : generateUuidV4Fallback();
    }

    if (optNoHyphens.checked) {
      u = u.replace(/-/g, '');
    }
    if (optUppercase.checked) {
      u = u.toUpperCase();
    } else {
      u = u.toLowerCase();
    }
    if (optBraces.checked) {
      u = `{${u}}`;
    }
    return u;
  }

  function generateUuidV4Fallback() {
    return '10000000-1000-4000-8000-100000000000'.replace(/[018]/g, c =>
      (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16)
    );
  }

  function runUuidGeneration() {
    const version = document.querySelector('input[name="uuidVersion"]:checked').value;
    const count = parseInt(uuidCount.value, 10) || 1;

    if (count === 1) {
      const id = generateSingleUuid(version);
      primaryUuidDisplay.textContent = id;
      uuidSingleContainer.style.display = 'flex';
      uuidMultiContainer.style.display = 'none';
      uuidResultsTextarea.value = id;
    } else {
      const list = [];
      for (let i = 0; i < count; i++) {
        list.push(generateSingleUuid(version));
      }
      uuidResultsTextarea.value = list.join('\n');
      primaryUuidDisplay.textContent = list[0];
      uuidSingleContainer.style.display = 'none';
      uuidMultiContainer.style.display = 'block';
    }
  }

  generateUuidBtn.addEventListener('click', () => {
    runUuidGeneration();
    showToast('Generated fresh UUID(s)');
  });

  copySingleUuidBtn.addEventListener('click', async () => {
    const val = primaryUuidDisplay.textContent;
    if (val && val !== '-') {
      try {
        await navigator.clipboard.writeText(val);
        showToast('Copied UUID to clipboard!');
      } catch {
        showToast('Failed to copy');
      }
    }
  });

  copyAllUuidBtn.addEventListener('click', async () => {
    const val = uuidResultsTextarea.value;
    if (val) {
      try {
        await navigator.clipboard.writeText(val);
        showToast('Copied all UUIDs to clipboard!');
      } catch {
        showToast('Failed to copy');
      }
    }
  });

  downloadUuidBtn.addEventListener('click', () => {
    const val = uuidResultsTextarea.value;
    if (!val) return;
    const blob = new Blob([val], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `uuids-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Downloaded UUID text file!');
  });

  // Re-run format options on toggle
  [optNoHyphens, optUppercase, optBraces].forEach(cb => {
    cb.addEventListener('change', runUuidGeneration);
  });
  document.querySelectorAll('input[name="uuidVersion"]').forEach(rb => {
    rb.addEventListener('change', runUuidGeneration);
  });
  uuidCount.addEventListener('change', runUuidGeneration);

  // --------------------------------------------------------------------------
  // 5. UUID Inspector / Validator
  // --------------------------------------------------------------------------
  const inspectInput = document.getElementById('inspectInput');
  const inspectSampleBtn = document.getElementById('inspectSampleBtn');
  const inspectResultBox = document.getElementById('inspectResultBox');
  const insValid = document.getElementById('insValid');
  const insVersion = document.getElementById('insVersion');
  const insVariant = document.getElementById('insVariant');
  const insTimestamp = document.getElementById('insTimestamp');

  function inspectUuid() {
    const raw = inspectInput.value.trim().replace(/^\{/, '').replace(/\}$/, '');
    if (!raw) {
      inspectResultBox.style.display = 'none';
      return;
    }

    inspectResultBox.style.display = 'grid';
    // Match standard hyphenated or non-hyphenated 32-hex
    const regex = /^[0-9a-f]{8}-?[0-9a-f]{4}-?([0-9a-f])[0-9a-f]{3}-?([0-9a-f])[0-9a-f]{3}-?[0-9a-f]{12}$/i;
    const match = raw.match(regex);

    if (!match) {
      insValid.textContent = '❌ Invalid UUID';
      insValid.className = 'ins-val invalid';
      insVersion.textContent = '-';
      insVariant.textContent = '-';
      insTimestamp.textContent = '-';
      return;
    }

    insValid.textContent = '✅ Valid RFC UUID';
    insValid.className = 'ins-val valid';

    const versionHex = match[1].toLowerCase();
    const variantHex = match[2].toLowerCase();

    // Determine version
    let versionStr = `Version ${versionHex}`;
    if (versionHex === '1') versionStr += ' (Gregorian Time)';
    else if (versionHex === '2') versionStr += ' (DCE Security)';
    else if (versionHex === '3') versionStr += ' (MD5 Name)';
    else if (versionHex === '4') versionStr += ' (Cryptographic Random)';
    else if (versionHex === '5') versionStr += ' (SHA-1 Name)';
    else if (versionHex === '7') versionStr += ' (Unix Epoch Time-Ordered)';
    insVersion.textContent = versionStr;

    // Determine variant (bits of the variant nibble)
    const varInt = parseInt(variantHex, 16);
    let variantStr = 'Unknown';
    if ((varInt & 0x8) === 0) variantStr = 'NCS Backward Compatible (0xxx)';
    else if ((varInt & 0xc) === 0x8) variantStr = 'RFC 4122 / Leach-Salz (10xx)';
    else if ((varInt & 0xe) === 0xc) variantStr = 'Microsoft GUID (110x)';
    else variantStr = 'Reserved for Future Definition';
    insVariant.textContent = variantStr;

    // Check embedded timestamp
    if (versionHex === '7') {
      const cleanHex = raw.replace(/-/g, '');
      const timeHex = cleanHex.slice(0, 12);
      const epochMs = parseInt(timeHex, 16);
      const date = new Date(epochMs);
      if (!isNaN(date.getTime())) {
        insTimestamp.textContent = `${date.toISOString()} (${epochMs})`;
      } else {
        insTimestamp.textContent = 'Invalid timestamp';
      }
    } else if (versionHex === '1') {
      const cleanHex = raw.replace(/-/g, '');
      const timeLow = cleanHex.slice(0, 8);
      const timeMid = cleanHex.slice(8, 12);
      const timeHi = cleanHex.slice(13, 16);
      const time100ns = BigInt('0x' + timeHi + timeMid + timeLow);
      const epochMs = Number((time100ns - 122192928000000000n) / 10000n);
      const date = new Date(epochMs);
      if (!isNaN(date.getTime())) {
        insTimestamp.textContent = `${date.toISOString()}`;
      } else {
        insTimestamp.textContent = 'Unsupported v1 clock format';
      }
    } else {
      insTimestamp.textContent = 'N/A (Non-time-based version)';
    }
  }

  inspectInput.addEventListener('input', inspectUuid);
  inspectSampleBtn.addEventListener('click', () => {
    inspectInput.value = generateUuidV7();
    inspectUuid();
    showToast('Loaded sample UUID v7 into inspector');
  });

  // --------------------------------------------------------------------------
  // 6. Text Hash Generator
  // --------------------------------------------------------------------------
  const hashTextInput = document.getElementById('hashTextInput');
  const hashUppercase = document.getElementById('hashUppercase');
  const clearHashTextBtn = document.getElementById('clearHashTextBtn');
  const sampleHashTextBtn = document.getElementById('sampleHashTextBtn');

  const outSha256 = document.getElementById('outSha256');
  const outMd5 = document.getElementById('outMd5');
  const outSha512 = document.getElementById('outSha512');
  const outSha384 = document.getElementById('outSha384');
  const outSha1 = document.getElementById('outSha1');

  async function calculateSubtleHash(algorithm, buffer) {
    const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function updateHashes() {
    const text = hashTextInput.value;
    if (!text) {
      [outSha256, outMd5, outSha512, outSha384, outSha1].forEach(el => {
        el.value = '';
      });
      return;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const isUpper = hashUppercase.checked;

    try {
      // Native Web Crypto
      const [sha256Hex, sha512Hex, sha384Hex, sha1Hex] = await Promise.all([
        calculateSubtleHash('SHA-256', data),
        calculateSubtleHash('SHA-512', data),
        calculateSubtleHash('SHA-384', data),
        calculateSubtleHash('SHA-1', data)
      ]);

      // MD5
      const md5Hex = md5(text);

      outSha256.value = isUpper ? sha256Hex.toUpperCase() : sha256Hex;
      outMd5.value = isUpper ? md5Hex.toUpperCase() : md5Hex;
      outSha512.value = isUpper ? sha512Hex.toUpperCase() : sha512Hex;
      outSha384.value = isUpper ? sha384Hex.toUpperCase() : sha384Hex;
      outSha1.value = isUpper ? sha1Hex.toUpperCase() : sha1Hex;
    } catch (err) {
      console.error('Hash calculation error:', err);
    }
  }

  hashTextInput.addEventListener('input', updateHashes);
  hashUppercase.addEventListener('change', updateHashes);

  clearHashTextBtn.addEventListener('click', () => {
    hashTextInput.value = '';
    updateHashes();
    hashTextInput.focus();
  });

  sampleHashTextBtn.addEventListener('click', () => {
    hashTextInput.value = 'The quick brown fox jumps over the lazy dog';
    updateHashes();
    showToast('Loaded sample text');
  });

  // Global handler for copy-hash-btn
  document.querySelectorAll('.copy-hash-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetId = btn.getAttribute('data-target');
      const val = document.getElementById(targetId)?.value;
      if (val) {
        try {
          await navigator.clipboard.writeText(val);
          showToast('Copied hash to clipboard!');
        } catch {
          showToast('Failed to copy');
        }
      }
    });
  });

  // --------------------------------------------------------------------------
  // 7. Client-Side File Checksum
  // --------------------------------------------------------------------------
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const fileInfoBox = document.getElementById('fileInfoBox');
  const fileName = document.getElementById('fileName');
  const fileSize = document.getElementById('fileSize');
  const hashProgressBadge = document.getElementById('hashProgressBadge');
  const fileHashesContainer = document.getElementById('fileHashesContainer');
  const fileSha256 = document.getElementById('fileSha256');
  const fileMd5 = document.getElementById('fileMd5');
  const fileSha1 = document.getElementById('fileSha1');

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async function processFile(file) {
    if (!file) return;

    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    hashProgressBadge.textContent = 'Computing Hashes...';
    hashProgressBadge.style.background = 'var(--primary-light)';
    hashProgressBadge.style.color = 'var(--primary)';
    fileInfoBox.style.display = 'flex';
    fileHashesContainer.style.display = 'flex';

    fileSha256.value = 'Calculating...';
    fileMd5.value = 'Calculating...';
    fileSha1.value = 'Calculating...';

    try {
      const buffer = await file.arrayBuffer();
      const [sha256Hex, sha1Hex] = await Promise.all([
        calculateSubtleHash('SHA-256', buffer),
        calculateSubtleHash('SHA-1', buffer)
      ]);
      const md5Hex = md5ArrayBuffer(buffer);

      fileSha256.value = sha256Hex;
      fileMd5.value = md5Hex;
      fileSha1.value = sha1Hex;

      hashProgressBadge.textContent = '✅ Verified';
      hashProgressBadge.style.background = 'var(--accent-light)';
      hashProgressBadge.style.color = 'var(--accent)';
      showToast('File checksums computed successfully!');
    } catch (err) {
      hashProgressBadge.textContent = 'Error';
      showToast(`Error processing file: ${err.message}`);
    }
  }

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  });

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  });

  // --------------------------------------------------------------------------
  // 8. HMAC Calculator
  // --------------------------------------------------------------------------
  const hmacAlgorithm = document.getElementById('hmacAlgorithm');
  const hmacSecret = document.getElementById('hmacSecret');
  const hmacMessage = document.getElementById('hmacMessage');
  const outHmacHex = document.getElementById('outHmacHex');
  const outHmacB64 = document.getElementById('outHmacB64');

  async function calculateHmac() {
    const keyStr = hmacSecret.value;
    const msgStr = hmacMessage.value;
    const algo = hmacAlgorithm.value;

    if (!keyStr || !msgStr) {
      outHmacHex.value = '';
      outHmacB64.value = '';
      return;
    }

    try {
      const encoder = new TextEncoder();
      const keyData = encoder.encode(keyStr);
      const msgData = encoder.encode(msgStr);

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: algo },
        false,
        ['sign']
      );

      const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
      const sigBytes = new Uint8Array(signatureBuffer);

      // Hex format
      const hex = Array.from(sigBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      outHmacHex.value = hex;

      // Base64 format
      let binary = '';
      sigBytes.forEach(b => binary += String.fromCharCode(b));
      outHmacB64.value = btoa(binary);
    } catch (err) {
      outHmacHex.value = `Error: ${err.message}`;
      outHmacB64.value = '';
    }
  }

  hmacAlgorithm.addEventListener('change', calculateHmac);
  hmacSecret.addEventListener('input', calculateHmac);
  hmacMessage.addEventListener('input', calculateHmac);

  // Generate initial single UUID
  runUuidGeneration();
});
