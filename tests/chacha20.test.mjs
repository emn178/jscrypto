import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { createClassicRegistry } from './helpers/classic-registry.mjs';
import { createRegistry } from '@jscrypto/core';
import {
  chacha20,
  chacha20Poly1305,
  chacha20Preset,
  xchacha20,
  xchacha20Poly1305,
} from '../packages/ciphers/dist/chacha20.mjs';

const require = createRequire(import.meta.url);

function hex(value) {
  return Uint8Array.from(Buffer.from(value.replace(/\s+/g, ''), 'hex'));
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function utf8(value) {
  return new TextEncoder().encode(value);
}

const ladies = utf8(
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
);

const dhole = utf8(
  'The dhole (pronounced "dole") is also known as the Asiatic wild dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.',
);

// RFC 8439 §2.4.2
const rfcChaCha20 = {
  key: hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
  nonce: hex('000000000000004a00000000'),
  counter: 1,
  plaintext: ladies,
  ciphertext: hex(
    '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b' +
      'f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8' +
      '07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736' +
      '5af90bbf74a35be6b40b8eedf2785e42874d',
  ),
};

// RFC 8439 §2.8.2
const rfcAead = {
  key: hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
  nonce: hex('070000004041424344454647'),
  aad: hex('50515253c0c1c2c3c4c5c6c7'),
  plaintext: ladies,
  sealed: hex(
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
      '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
      '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
      '3ff4def08e4b7a9de576d26586cec64b6116' +
      '1ae10b594f09e26a7e902ecbd0600691',
  ),
};

// draft-irtf-cfrg-xchacha-03 Appendix A.2.1
const draftXChaCha20 = {
  key: hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
  nonce: hex('404142434445464748494a4b4c4d4e4f5051525354555658'),
  plaintext: dhole,
  ciphertext: hex(
    '4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9' +
      '8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d' +
      '4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da' +
      'ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744' +
      '3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240' +
      '7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c' +
      '09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae' +
      '577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c' +
      'cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663' +
      '93b93111c1a55dd7421a10184974c7c5',
  ),
};

// draft-irtf-cfrg-xchacha-03 Appendix A.1
const draftXAead = {
  key: hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
  nonce: hex('404142434445464748494a4b4c4d4e4f5051525354555657'),
  aad: hex('50515253c0c1c2c3c4c5c6c7'),
  plaintext: ladies,
  sealed: hex(
    'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
      '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
      '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
      '21f9664c97637da9768812f615c68b13b5' +
      '2ec0875924c1c7987947deafd8780acf49',
  ),
};

function createChaChaRegistry() {
  return createRegistry().use(chacha20Preset);
}

function encryptChaCha20({ key, nonce, data, counter }) {
  return createChaChaRegistry().createCipher({
    cipher: 'ChaCha20',
    key,
    nonce,
    counter,
  }).encrypt(data);
}

function decryptChaCha20({ key, nonce, data, counter }) {
  return createChaChaRegistry().createCipher({
    cipher: 'ChaCha20',
    key,
    nonce,
    counter,
  }).decrypt(data);
}

function encryptXChaCha20({ key, nonce, data, counter }) {
  return createChaChaRegistry().createCipher({
    cipher: 'XChaCha20',
    key,
    nonce,
    counter,
  }).encrypt(data);
}

function decryptXChaCha20({ key, nonce, data, counter }) {
  return createChaChaRegistry().createCipher({
    cipher: 'XChaCha20',
    key,
    nonce,
    counter,
  }).decrypt(data);
}

function sealChaCha20Poly1305({ key, nonce, plaintext, aad }) {
  return createChaChaRegistry().createAead({
    algorithm: 'ChaCha20-Poly1305',
    key,
  }).seal(plaintext, { nonce, aad });
}

function openChaCha20Poly1305({ key, nonce, ciphertext, aad, tag }) {
  return createChaChaRegistry().createAead({
    algorithm: 'ChaCha20-Poly1305',
    key,
  }).open(ciphertext, { nonce, aad, tag });
}

function sealXChaCha20Poly1305({ key, nonce, plaintext, aad }) {
  return createChaChaRegistry().createAead({
    algorithm: 'XChaCha20-Poly1305',
    key,
  }).seal(plaintext, { nonce, aad });
}

function openXChaCha20Poly1305({ key, nonce, ciphertext, aad, tag }) {
  return createChaChaRegistry().createAead({
    algorithm: 'XChaCha20-Poly1305',
    key,
  }).open(ciphertext, { nonce, aad, tag });
}

test('RFC 8439 ChaCha20 encryption vector', () => {
  const ciphertext = encryptChaCha20({
    key: rfcChaCha20.key,
    nonce: rfcChaCha20.nonce,
    data: rfcChaCha20.plaintext,
    counter: rfcChaCha20.counter,
  });
  assert.equal(toHex(ciphertext), toHex(rfcChaCha20.ciphertext));
  assert.equal(
    toHex(decryptChaCha20({
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      data: ciphertext,
      counter: rfcChaCha20.counter,
    })),
    toHex(rfcChaCha20.plaintext),
  );
});

test('draft XChaCha20 encryption vector', () => {
  const ciphertext = encryptXChaCha20({
    key: draftXChaCha20.key,
    nonce: draftXChaCha20.nonce,
    data: draftXChaCha20.plaintext,
  });
  assert.equal(toHex(ciphertext), toHex(draftXChaCha20.ciphertext));
  assert.equal(
    toHex(decryptXChaCha20({
      key: draftXChaCha20.key,
      nonce: draftXChaCha20.nonce,
      data: ciphertext,
    })),
    toHex(draftXChaCha20.plaintext),
  );
});

test('RFC 8439 ChaCha20-Poly1305 seal/open vector', () => {
  const sealed = sealChaCha20Poly1305({
    key: rfcAead.key,
    nonce: rfcAead.nonce,
    plaintext: rfcAead.plaintext,
    aad: rfcAead.aad,
  });
  assert.equal(toHex(sealed), toHex(rfcAead.sealed));
  assert.equal(
    toHex(openChaCha20Poly1305({
      key: rfcAead.key,
      nonce: rfcAead.nonce,
      ciphertext: sealed,
      aad: rfcAead.aad,
    })),
    toHex(rfcAead.plaintext),
  );
});

test('draft XChaCha20-Poly1305 seal/open vector', () => {
  const sealed = sealXChaCha20Poly1305({
    key: draftXAead.key,
    nonce: draftXAead.nonce,
    plaintext: draftXAead.plaintext,
    aad: draftXAead.aad,
  });
  assert.equal(toHex(sealed), toHex(draftXAead.sealed));
  assert.equal(
    toHex(openXChaCha20Poly1305({
      key: draftXAead.key,
      nonce: draftXAead.nonce,
      ciphertext: sealed,
      aad: draftXAead.aad,
    })),
    toHex(draftXAead.plaintext),
  );
});

test('empty plaintext and empty AAD are allowed', () => {
  const key = rfcAead.key;
  const nonce = rfcAead.nonce;
  const sealed = sealChaCha20Poly1305({
    key,
    nonce,
    plaintext: new Uint8Array(0),
  });
  assert.equal(sealed.length, 16);
  assert.equal(
    toHex(openChaCha20Poly1305({ key, nonce, ciphertext: sealed })),
    '',
  );

  const withEmptyAad = sealChaCha20Poly1305({
    key,
    nonce,
    plaintext: utf8('hi'),
    aad: new Uint8Array(0),
  });
  assert.equal(
    toHex(openChaCha20Poly1305({
      key,
      nonce,
      ciphertext: withEmptyAad,
      aad: new Uint8Array(0),
    })),
    toHex(utf8('hi')),
  );
});

test('detached and appended tag decrypt flows', () => {
  const ciphertext = rfcAead.sealed.subarray(0, rfcAead.sealed.length - 16);
  const tag = rfcAead.sealed.subarray(rfcAead.sealed.length - 16);

  assert.equal(
    toHex(openChaCha20Poly1305({
      key: rfcAead.key,
      nonce: rfcAead.nonce,
      ciphertext,
      aad: rfcAead.aad,
      tag,
    })),
    toHex(rfcAead.plaintext),
  );

  const registry = createChaChaRegistry();
  const aead = registry.createAead({
    algorithm: 'ChaCha20-Poly1305',
    key: rfcAead.key,
  });
  assert.equal(
    toHex(aead.open(ciphertext, {
      nonce: rfcAead.nonce,
      aad: rfcAead.aad,
      tag,
    })),
    toHex(rfcAead.plaintext),
  );
  // When tag is present, mismatched tagLength is ignored.
  assert.equal(
    toHex(aead.open(ciphertext, {
      nonce: rfcAead.nonce,
      aad: rfcAead.aad,
      tag,
      tagLength: 12,
    })),
    toHex(rfcAead.plaintext),
  );
  assert.equal(
    toHex(aead.open(rfcAead.sealed, {
      nonce: rfcAead.nonce,
      aad: rfcAead.aad,
    })),
    toHex(rfcAead.plaintext),
  );
});

test('authentication failures reject wrong tag and wrong AAD', () => {
  const wrongTag = new Uint8Array(rfcAead.sealed);
  wrongTag[wrongTag.length - 1] ^= 0xff;
  assert.throws(
    () => openChaCha20Poly1305({
      key: rfcAead.key,
      nonce: rfcAead.nonce,
      ciphertext: wrongTag,
      aad: rfcAead.aad,
    }),
    /authentication failed/,
  );

  assert.throws(
    () => openChaCha20Poly1305({
      key: rfcAead.key,
      nonce: rfcAead.nonce,
      ciphertext: rfcAead.sealed,
      aad: hex('00'),
    }),
    /authentication failed/,
  );
});

test('invalid key, nonce, tag, and counter are rejected', () => {
  assert.throws(
    () => encryptChaCha20({
      key: new Uint8Array(16),
      nonce: rfcChaCha20.nonce,
      data: ladies,
    }),
    /key must be 256 bits/,
  );
  assert.throws(
    () => encryptChaCha20({
      key: rfcChaCha20.key,
      nonce: new Uint8Array(8),
      data: ladies,
    }),
    /nonce must be 96 bits/,
  );
  assert.throws(
    () => encryptXChaCha20({
      key: draftXChaCha20.key,
      nonce: new Uint8Array(12),
      data: dhole,
    }),
    /nonce must be 192 bits/,
  );
  assert.throws(
    () => encryptChaCha20({
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      data: ladies,
      counter: -1,
    }),
    /counter must be a 32-bit unsigned integer/,
  );
  assert.throws(
    () => encryptChaCha20({
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      data: ladies,
      counter: 0xffffffff,
    }),
    /counter must be a 32-bit unsigned integer/,
  );
  assert.throws(
    () => encryptChaCha20({
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      data: ladies,
      counter: 0x100000000,
    }),
    /counter must be a 32-bit unsigned integer/,
  );
  assert.equal(
    encryptChaCha20({
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      data: utf8('x'),
      counter: 0xfffffffe,
    }).length,
    1,
  );
  assert.throws(
    () => openChaCha20Poly1305({
      key: rfcAead.key,
      nonce: rfcAead.nonce,
      ciphertext: rfcAead.sealed.subarray(0, rfcAead.sealed.length - 16),
      aad: rfcAead.aad,
      tag: new Uint8Array(8),
    }),
    /tag must be 128 bits/,
  );
  assert.throws(
    () => openChaCha20Poly1305({
      key: rfcAead.key,
      nonce: rfcAead.nonce,
      ciphertext: new Uint8Array(8),
      aad: rfcAead.aad,
    }),
    /must include a 128-bit authentication tag/,
  );
});

test('raw ChaCha20 defaults counter to 0', () => {
  const withDefault = encryptChaCha20({
    key: rfcChaCha20.key,
    nonce: rfcChaCha20.nonce,
    data: utf8('abc'),
  });
  const withZero = encryptChaCha20({
    key: rfcChaCha20.key,
    nonce: rfcChaCha20.nonce,
    data: utf8('abc'),
    counter: 0,
  });
  assert.equal(toHex(withDefault), toHex(withZero));
  assert.notEqual(
    toHex(withDefault),
    toHex(encryptChaCha20({
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      data: utf8('abc'),
      counter: 1,
    })),
  );
});

test('preset registration with core and classic registries', () => {
  const coreRegistry = createChaChaRegistry();
  assert.equal(coreRegistry.has('cipher', 'ChaCha20'), true);
  assert.equal(coreRegistry.has('cipher', 'XChaCha20'), true);
  assert.equal(coreRegistry.has('aead', 'ChaCha20-Poly1305'), true);
  assert.equal(coreRegistry.has('aead', 'XChaCha20-Poly1305'), true);
  assert.equal(coreRegistry.has('cipher', 'ChaCha20-Poly1305'), false);
  assert.equal(coreRegistry.has('cipher', 'XChaCha20-Poly1305'), false);

  const classicRegistry = createClassicRegistry().use(chacha20Preset);
  const sealed = classicRegistry.createAead({
    algorithm: 'ChaCha20-Poly1305',
    key: rfcAead.key,
  }).seal(rfcAead.plaintext, {
    nonce: rfcAead.nonce,
    aad: rfcAead.aad,
  });
  assert.equal(toHex(sealed), toHex(rfcAead.sealed));
});

test('registry stream createCipher and AEAD createAead flows', () => {
  const registry = createChaChaRegistry();

  const stream = registry.createCipher({
    cipher: 'ChaCha20',
    key: rfcChaCha20.key,
    nonce: rfcChaCha20.nonce,
    counter: 1,
  });
  const streamCiphertext = stream.encrypt(rfcChaCha20.plaintext);
  assert.equal(toHex(streamCiphertext), toHex(rfcChaCha20.ciphertext));
  assert.equal(toHex(stream.decrypt(streamCiphertext)), toHex(rfcChaCha20.plaintext));

  const xstream = registry.createCipher({
    cipher: 'XChaCha20',
    key: draftXChaCha20.key,
    nonce: draftXChaCha20.nonce,
  });
  assert.equal(
    toHex(xstream.encrypt(draftXChaCha20.plaintext)),
    toHex(draftXChaCha20.ciphertext),
  );

  const aead = registry.createAead({
    algorithm: 'XChaCha20-Poly1305',
    key: draftXAead.key,
  });
  const sealed = aead.seal(draftXAead.plaintext, {
    nonce: draftXAead.nonce,
    aad: draftXAead.aad,
  });
  assert.equal(toHex(sealed), toHex(draftXAead.sealed));
  assert.equal(
    toHex(aead.open(sealed, {
      nonce: draftXAead.nonce,
      aad: draftXAead.aad,
    })),
    toHex(draftXAead.plaintext),
  );
});

test('mode is rejected for raw ChaCha20 stream but ignored for Poly1305 AEAD', () => {
  const registry = createChaChaRegistry();
  assert.throws(
    () => registry.createCipher({
      cipher: 'ChaCha20',
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      mode: 'CTR',
    }).encrypt(utf8('x')),
    /does not support mode/,
  );

  // The handoff documents that createAead has no padding and unrelated extra
  // fields such as `mode`/`padding` in the creation options have no effect
  // and must not throw by themselves.
  const sealed = registry.createAead({
    algorithm: 'ChaCha20-Poly1305',
    key: rfcAead.key,
    mode: 'CTR',
    padding: 'Pkcs7',
  }).seal(utf8('x'), { nonce: rfcAead.nonce });
  assert.equal(
    toHex(registry.createAead({
      algorithm: 'ChaCha20-Poly1305',
      key: rfcAead.key,
    }).open(sealed, { nonce: rfcAead.nonce })),
    toHex(utf8('x')),
  );
});

test('raw stream transforms emit chunks and match one-shot', () => {
  const oneshot = encryptChaCha20({
    key: rfcChaCha20.key,
    nonce: rfcChaCha20.nonce,
    data: rfcChaCha20.plaintext,
    counter: rfcChaCha20.counter,
  });

  const encryptor = chacha20.createEncryptor({
    key: rfcChaCha20.key,
    options: {
      cipher: 'ChaCha20',
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      counter: 1,
    },
  });
  assert.equal(encryptor.process(new Uint8Array(0)).length, 0);
  const part1 = encryptor.process(rfcChaCha20.plaintext.subarray(0, 10));
  const part2 = encryptor.process(rfcChaCha20.plaintext.subarray(10, 70));
  const part3 = encryptor.finalize(rfcChaCha20.plaintext.subarray(70));
  const streamed = new Uint8Array(part1.length + part2.length + part3.length);
  streamed.set(part1, 0);
  streamed.set(part2, part1.length);
  streamed.set(part3, part1.length + part2.length);

  assert.equal(part1.length, 10);
  assert.equal(part2.length, 60);
  assert.equal(toHex(streamed), toHex(oneshot));
  assert.equal(toHex(streamed), toHex(rfcChaCha20.ciphertext));
  assert.throws(() => encryptor.finalize(), /already finalized/);

  const emptyFinal = chacha20.createEncryptor({
    key: rfcChaCha20.key,
    options: {
      cipher: 'ChaCha20',
      key: rfcChaCha20.key,
      nonce: rfcChaCha20.nonce,
      counter: 1,
    },
  });
  assert.equal(emptyFinal.process(rfcChaCha20.plaintext).length, rfcChaCha20.plaintext.length);
  assert.equal(emptyFinal.finalize().length, 0);

  const xdecryptor = xchacha20.createDecryptor({
    key: draftXChaCha20.key,
    options: {
      cipher: 'XChaCha20',
      key: draftXChaCha20.key,
      nonce: draftXChaCha20.nonce,
    },
  });
  const xPart1 = xdecryptor.process(draftXChaCha20.ciphertext.subarray(0, 50));
  const xPart2 = xdecryptor.finalize(draftXChaCha20.ciphertext.subarray(50));
  const xPlain = new Uint8Array(xPart1.length + xPart2.length);
  xPlain.set(xPart1, 0);
  xPlain.set(xPart2, xPart1.length);
  assert.equal(xPart1.length, 50);
  assert.equal(toHex(xPlain), toHex(draftXChaCha20.plaintext));

  assert.throws(
    () => chacha20.createEncryptor({
      key: rfcChaCha20.key,
      options: undefined,
    }),
    /requires a nonce/,
  );
  assert.throws(
    () => xchacha20.createEncryptor({
      key: draftXChaCha20.key,
      options: {
        cipher: 'XChaCha20',
        key: draftXChaCha20.key,
      },
    }).finalize(dhole),
    /requires a nonce/,
  );
});

test('createAead seal/open roundtrip validates tagLength, nonce, and tag', () => {
  const registry = createChaChaRegistry();

  const sealed = registry.createAead({
    algorithm: 'XChaCha20-Poly1305',
    key: draftXAead.key,
  }).seal(draftXAead.plaintext, { nonce: draftXAead.nonce, aad: draftXAead.aad });
  assert.equal(toHex(sealed), toHex(draftXAead.sealed));
  assert.equal(
    toHex(registry.createAead({
      algorithm: 'XChaCha20-Poly1305',
      key: draftXAead.key,
    }).open(sealed, { nonce: draftXAead.nonce, aad: draftXAead.aad })),
    toHex(draftXAead.plaintext),
  );

  assert.throws(
    () => registry.createAead({
      algorithm: 'ChaCha20-Poly1305',
      key: rfcAead.key,
    }).seal(utf8('x'), { nonce: rfcAead.nonce, tagLength: 12 }),
    /tagLength must be 16/,
  );
  assert.throws(
    () => registry.createAead({
      algorithm: 'ChaCha20-Poly1305',
      key: rfcAead.key,
    }).open(rfcAead.sealed, { nonce: rfcAead.nonce, aad: rfcAead.aad, tagLength: 12 }),
    /tagLength must be 16/,
  );

  assert.throws(
    () => registry.createAead({
      algorithm: 'ChaCha20-Poly1305',
      key: rfcAead.key,
    }).seal(utf8('x'), {}),
    /ChaCha20-Poly1305 requires a nonce/,
  );
  assert.throws(
    () => registry.createAead({
      algorithm: 'XChaCha20-Poly1305',
      key: draftXAead.key,
    }).open(draftXAead.sealed, {}),
    /XChaCha20-Poly1305 requires a nonce/,
  );

  const wrongTag = new Uint8Array(rfcAead.sealed);
  wrongTag[wrongTag.length - 1] ^= 0xff;
  assert.throws(
    () => registry.createAead({
      algorithm: 'ChaCha20-Poly1305',
      key: rfcAead.key,
    }).open(wrongTag, { nonce: rfcAead.nonce, aad: rfcAead.aad }),
    /ChaCha20-Poly1305 authentication failed/,
  );
});

test('component metadata matches the public surface', () => {
  assert.equal(chacha20.name, 'ChaCha20');
  assert.equal(chacha20.kind, 'cipher');
  assert.equal(chacha20.type, 'stream');
  assert.deepEqual(chacha20.keySizes, [32]);
  assert.equal(xchacha20.name, 'XChaCha20');
  assert.equal(xchacha20.kind, 'cipher');

  assert.equal(chacha20Poly1305.name, 'ChaCha20-Poly1305');
  assert.equal(chacha20Poly1305.kind, 'aead');
  assert.deepEqual(chacha20Poly1305.nonceSizes, [12]);
  assert.deepEqual(chacha20Poly1305.tagSizes, [16]);
  assert.equal(typeof chacha20Poly1305.create, 'function');
  assert.equal(chacha20Poly1305.createEncryptor, undefined);
  assert.equal(chacha20Poly1305.createDecryptor, undefined);

  assert.equal(xchacha20Poly1305.name, 'XChaCha20-Poly1305');
  assert.equal(xchacha20Poly1305.kind, 'aead');
  assert.deepEqual(xchacha20Poly1305.nonceSizes, [24]);
  assert.deepEqual(xchacha20Poly1305.tagSizes, [16]);
  assert.equal(typeof xchacha20Poly1305.create, 'function');
  assert.equal(xchacha20Poly1305.createEncryptor, undefined);
  assert.equal(xchacha20Poly1305.createDecryptor, undefined);

  assert.equal(chacha20Preset.name, 'chacha20');
  assert.deepEqual(
    [...chacha20Preset.components()].map((component) => component.name),
    ['ChaCha20', 'XChaCha20', 'ChaCha20-Poly1305', 'XChaCha20-Poly1305'],
  );
});

test('after migration, createCipher no longer resolves ChaCha AEAD names', () => {
  const registry = createChaChaRegistry();
  assert.throws(
    () => registry.createCipher({ cipher: 'ChaCha20-Poly1305', key: rfcAead.key }).encrypt(utf8('x')),
    /Component not found: cipher:ChaCha20-Poly1305/,
  );
  assert.throws(
    () => registry.createCipher({ cipher: 'XChaCha20-Poly1305', key: draftXAead.key }).encrypt(utf8('x')),
    /Component not found: cipher:XChaCha20-Poly1305/,
  );
});

test('CommonJS build can be required', () => {
  const packageExports = require('../packages/ciphers/dist/chacha20.cjs');
  assert.equal(typeof packageExports.chacha20.createEncryptor, 'function');
  assert.equal(packageExports.chacha20.name, 'ChaCha20');
  assert.equal(packageExports.xchacha20.name, 'XChaCha20');
  assert.equal(packageExports.chacha20Poly1305.name, 'ChaCha20-Poly1305');
  assert.equal(packageExports.chacha20Poly1305.kind, 'aead');
  assert.equal(typeof packageExports.chacha20Poly1305.create, 'function');
  assert.equal(packageExports.xchacha20Poly1305.name, 'XChaCha20-Poly1305');
  assert.equal(packageExports.xchacha20Poly1305.kind, 'aead');
  assert.equal(typeof packageExports.xchacha20Poly1305.create, 'function');
});

test('generated declarations export the public API', async () => {
  const dts = await readFile(new URL('../packages/ciphers/dist/chacha20.d.ts', import.meta.url), 'utf8');
  assert.match(dts, /export declare const chacha20:/);
  assert.match(dts, /export declare const xchacha20:/);
  assert.match(dts, /export declare const chacha20Poly1305:\s*AeadComponent/);
  assert.match(dts, /export declare const xchacha20Poly1305:\s*AeadComponent/);
  assert.match(dts, /export declare const chacha20Preset:/);
  assert.doesNotMatch(dts, /export declare function encryptChaCha20/);
  assert.doesNotMatch(dts, /export declare function sealXChaCha20Poly1305/);
  assert.doesNotMatch(dts, /export declare function openXChaCha20Poly1305/);
});
