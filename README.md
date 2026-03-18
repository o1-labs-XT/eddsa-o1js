# eddsa-o1js

> ⚠️ **NOTE**: This library requires the [o1js native prover](https://www.o1js.dev/prerelease-native-prover) prerelease to generate proofs, as the circuit (~233k rows) exceeds the standard WASM prover limit (2^16 rows). Proof generation with chunking is not yet working in the current prerelease — execution mode (`proofsEnabled: false`) works end-to-end.

![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
[![npm version](https://img.shields.io/npm/v/eddsa-o1js.svg)](https://www.npmjs.com/package/eddsa-o1js)

A provable EdDSA signature verification library for [o1js](https://github.com/o1-labs/o1js), enabling zkApp developers to verify EdDSA signatures inside zk-SNARKs.

## Features

- **EdDSA Verification in ZK**: Verify EdDSA signatures within provable o1js code
- **Edwards25519 Support**: Built-in support for the popular Edwards25519 curve
- **RFC 8032 Compliant**: Signing and verification match the [Ed25519 specification](https://www.rfc-editor.org/rfc/rfc8032)
- **Fully Composable**: Designed to work seamlessly with the o1js ecosystem

## Installation

```bash
npm install eddsa-o1js o1js@2.10.0-dev.e7f2f @o1js/native@2.10.0-dev.e7f2f
```

## Usage

```typescript
import { setBackend } from 'o1js';
setBackend('native');

import { ZkProgram, Bool, Bytes } from 'o1js';
import { createEddsa, createForeignTwisted, TwistedCurves, derivePublicKey } from 'eddsa-o1js';

// Create curve and signature classes
class Edwards25519 extends createForeignTwisted(TwistedCurves.Edwards25519) {}
class Eddsa extends createEddsa(Edwards25519) {}
class Bytes32 extends Bytes(32) {}

// Define a ZkProgram that verifies EdDSA signatures
const eddsa = ZkProgram({
  name: 'eddsa',
  numChunks: 4,
  overrideWrapDomain: 2,
  publicInput: Bytes32,
  publicOutput: Bool,

  methods: {
    verifyEddsa: {
      privateInputs: [Eddsa, Edwards25519],
      async method(
        message: Bytes32,
        signature: Eddsa,
        publicKey: Edwards25519
      ) {
        return {
          publicOutput: signature.verify(message, publicKey),
        };
      },
    },
  },
});

// Generate a keypair (RFC 8032: seed -> SHA-512 -> scalar -> public key)
let seed = Edwards25519.Scalar.random();
let publicKey = new Edwards25519(derivePublicKey(seed.toBigInt()));

// Sign a message
let message = Bytes32.fromString('Hello, o1js!');
let signature = Eddsa.sign(message.toBytes(), seed.toBigInt());

// Verify in execution mode
await eddsa.compile({ proofsEnabled: false });
let { proof } = await eddsa.verifyEddsa(message, signature, publicKey);
proof.publicOutput.assertTrue('signature verifies');
```

## Key Derivation

EdDSA (RFC 8032) derives the signing scalar from a 32-byte seed via SHA-512. Use `derivePublicKey` to get the public key that corresponds to a seed:

```typescript
import { derivePublicKey } from 'eddsa-o1js';

let seed = Edwards25519.Scalar.random();
let publicKey = new Edwards25519(derivePublicKey(seed.toBigInt()));
let signature = Eddsa.sign(message.toBytes(), seed.toBigInt());
```

Do not use `Edwards25519.generator.scale(seed)` as the public key — that computes `[seed]B` directly, while `Eddsa.sign` internally derives a different scalar via `SHA-512(seed)`.

## Advanced Usage

For more detailed examples, please check the [examples directory](./examples):

- [ZkProgram definition](./examples/eddsa.ts)
- [Running a complete example](./examples/run.ts)

## API Reference

### Core Components

- `createEddsa(TwistedCurve)`: Factory function that creates an EdDSA implementation for a specific curve
- `createForeignTwisted(TwistedCurveParams)`: Creates a provable twisted Edwards curve implementation
- `TwistedCurves`: Contains parameters for common twisted Edwards curves (e.g., Edwards25519)
- `derivePublicKey(seed)`: Derives the Ed25519 public key point from a 32-byte seed per RFC 8032

### Usage Patterns

1. Define your curve by extending the base implementation
2. Create your EdDSA implementation for that curve
3. Use `derivePublicKey` to derive keypairs from seeds
4. Use the signature verification methods in your ZkProgram

## Development

```bash
# Build the project
npm run build

# Run the example (execution mode)
node --experimental-vm-modules build/examples/run.js
```

## Related Projects

- [o1js](https://github.com/o1-labs/o1js) - The main framework for writing zero-knowledge applications

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.
