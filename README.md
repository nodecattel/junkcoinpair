# junkcoinpair

[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

A library for managing SECP256k1 keypairs for JunkCoin, written in TypeScript with transpiled JavaScript committed to git.

## Installation

```bash
npm install junkcoinpair
```

## Example

TypeScript
```typescript
import { ECPairFactory, ECPairInterface } from 'junkcoinpair';
import * as crypto from 'crypto';

// Initialize with tiny-secp256k1
const tinysecp = require('tiny-secp256k1');
const ECPair = ECPairFactory(tinysecp);

// Generate random keypair
const keyPair = ECPair.makeRandom();

// Create from WIF
const fromWif = ECPair.fromWIF('your_wif_key_here');

// Create from private key
const fromPrivate = ECPair.fromPrivateKey(crypto.randomBytes(32));

// Create from public key (33 or 65 byte DER format)
const fromPublic = ECPair.fromPublicKey(keyPair.publicKey);

// Sign a message
const message = crypto.createHash('sha256').update('hello world').digest();
const signature = keyPair.sign(message);

// Verify a signature
const isValid = keyPair.verify(message, signature);
```

## Features

- Generate random keypairs
- Import/export private keys in WIF format
- Create keypairs from private or public keys
- Sign messages and verify signatures
- Support for compressed and uncompressed public keys
- Schnorr signature support (when available)
- TypeScript support with full type definitions

## API

### ECPairFactory(secp256k1)
Creates an ECPair API using the provided secp256k1 implementation.

### ECPair Methods

- `makeRandom([options])`: Generate a random keypair
- `fromPrivateKey(buffer[, options])`: Create a keypair from a private key
- `fromPublicKey(buffer[, options])`: Create a keypair from a public key
- `fromWIF(string)`: Create a keypair from a WIF string

### Instance Methods

- `sign(hash)`: Sign a 32-byte hash
- `verify(hash, signature)`: Verify a signature
- `toWIF()`: Export private key as WIF
- `tweak(buffer)`: Derive a new keypair by tweaking the current one

## Testing

```bash
npm test
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](LICENSE)

Based on [bitcoinjs/ecpair](https://github.com/bitcoinjs/ecpair), modified for JunkCoin.
