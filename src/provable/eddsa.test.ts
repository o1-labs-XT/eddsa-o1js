import { setBackend } from 'o1js';
setBackend('native');

import { initializeBindings, Bytes, Provable } from 'o1js';
import { createEddsa } from './eddsa.js';
import { createForeignTwisted, TwistedCurves, derivePublicKey } from './twisted-curve.js';

class Edwards25519 extends createForeignTwisted(TwistedCurves.Edwards25519) {}
class Eddsa extends createEddsa(Edwards25519) {}
class Bytes32 extends Bytes(32) {}

await initializeBindings();

function hexToSeed(hex: string): bigint {
  let result = 0n;
  for (let i = 0; i < hex.length; i += 2) {
    result += BigInt(parseInt(hex.slice(i, i + 2), 16)) << BigInt((i / 2) * 8);
  }
  return result;
}

function encToHex(value: bigint): string {
  let hex = '';
  for (let i = 0; i < 32; i++) {
    hex += ((value >> BigInt(i * 8)) & 0xffn).toString(16).padStart(2, '0');
  }
  return hex;
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error('FAIL: ' + msg);
  console.log('  ✓ ' + msg);
}

let failures = 0;

// RFC 8032 Section 7.1 — Ed25519 test vectors

console.log('RFC 8032 test vectors');

// Test vector 1: empty message
{
  let seed = hexToSeed('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  let pk = derivePublicKey(seed);
  let pkEnc = pk.y | ((pk.x & 1n) << 255n);
  assert(encToHex(pkEnc) === 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'vector 1: public key');

  let sig = Eddsa.sign([], seed);
  let s = sig.toBigInt();
  assert(encToHex(s.R) === 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155', 'vector 1: signature R');
  assert(encToHex(s.s) === '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'vector 1: signature s');
}

// Test vector 2: 1-byte message 0x72
{
  let seed = hexToSeed('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
  let pk = derivePublicKey(seed);
  let pkEnc = pk.y | ((pk.x & 1n) << 255n);
  assert(encToHex(pkEnc) === '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', 'vector 2: public key');

  let sig = Eddsa.sign([0x72], seed);
  let s = sig.toBigInt();
  assert(encToHex(s.R) === '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da', 'vector 2: signature R');
  assert(encToHex(s.s) === '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', 'vector 2: signature s');
}

// Test vector 3: 2-byte message 0xaf82
{
  let seed = hexToSeed('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7');
  let pk = derivePublicKey(seed);
  let pkEnc = pk.y | ((pk.x & 1n) << 255n);
  assert(encToHex(pkEnc) === 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'vector 3: public key');

  let sig = Eddsa.sign([0xaf, 0x82], seed);
  let s = sig.toBigInt();
  assert(encToHex(s.R) === '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac', 'vector 3: signature R');
  assert(encToHex(s.s) === '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a', 'vector 3: signature s');
}

// Sign and verify round-trip

console.log('\nconstant mode: 10 random round-trips');
for (let i = 0; i < 10; i++) {
  let seed = Edwards25519.Scalar.random();
  let pk = new Edwards25519(derivePublicKey(seed.toBigInt()));
  let msg = Bytes32.fromString('test ' + i);
  let sig = Eddsa.sign(msg.toBytes(), seed.toBigInt());
  assert(sig.verify(msg, pk).toBoolean(), `round-trip ${i}`);
}

console.log('\nprovable mode: verify passes runAndCheck');
{
  let seed = Edwards25519.Scalar.random();
  let pk = new Edwards25519(derivePublicKey(seed.toBigInt()));
  let msg = Bytes32.fromString('provable test');
  let sig = Eddsa.sign(msg.toBytes(), seed.toBigInt());

  await Provable.runAndCheck(async () => {
    let sigW = Provable.witness(Eddsa.provable, () => sig);
    let msgW = Provable.witness(Bytes32, () => msg);
    let pkW = Provable.witness(Edwards25519.provable, () => pk);
    sigW.verify(msgW, pkW).assertTrue('signature must verify');
  });
}

console.log('\nall tests passed');
