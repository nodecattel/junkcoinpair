import * as assert from 'assert';
import { describe, it } from 'mocha';
import { ECPairFactory } from '../ts_src';
import { createHash } from 'crypto';

const tinysecp = require('tiny-secp256k1');
const ECPair = ECPairFactory(tinysecp);

describe('JunkCoinPair', () => {
  describe('Key Generation', () => {
    it('should generate random keypair', () => {
      const keyPair = ECPair.makeRandom();
      assert.strictEqual(keyPair.privateKey!.length, 32);
      assert.strictEqual(keyPair.compressed, true);
    });

    it('should support custom RNG', () => {
      const rng = (size: number): Buffer => Buffer.alloc(size, 1);
      const keyPair = ECPair.makeRandom({ rng });
      assert.strictEqual(keyPair.privateKey!.length, 32);
    });

    it('should create key pair from private key', () => {
      const privKey = Buffer.alloc(32, 1);
      const keyPair = ECPair.fromPrivateKey(privKey);
      assert.strictEqual(
        keyPair.privateKey!.toString('hex'),
        privKey.toString('hex'),
      );
    });

    it('should handle uncompressed public keys', () => {
      const keyPair = ECPair.makeRandom({ compressed: false });
      assert.strictEqual(keyPair.compressed, false);
      const pubKey = keyPair.publicKey;
      assert.strictEqual(pubKey.length === 65 || pubKey.length === 33, true);
    });

    it('should throw on invalid private key', () => {
      const invalidPrivKey = Buffer.alloc(31); // Wrong length
      assert.throws(() => {
        ECPair.fromPrivateKey(invalidPrivKey);
      }, /Expected Buffer\(Length: 32\)/);
    });
  });

  describe('Public Key Operations', () => {
    it('should create from public key', () => {
      const keyPair = ECPair.makeRandom();
      const pubOnlyPair = ECPair.fromPublicKey(keyPair.publicKey);
      assert.strictEqual(
        pubOnlyPair.publicKey.toString('hex'),
        keyPair.publicKey.toString('hex'),
      );
    });

    it('should lazily generate public key', () => {
      const keyPair = ECPair.makeRandom();
      assert.strictEqual(Buffer.isBuffer(keyPair.privateKey), true);
      const pubKey = keyPair.publicKey;
      assert.strictEqual(Buffer.isBuffer(pubKey), true);
    });
  });

  describe('WIF', () => {
    it('should do WIF roundtrip', () => {
      const keyPair = ECPair.makeRandom();
      const wif = keyPair.toWIF();
      const imported = ECPair.fromWIF(wif);
      assert.strictEqual(
        imported.privateKey!.toString('hex'),
        keyPair.privateKey!.toString('hex'),
      );
    });

    it('should maintain compressed flag in WIF', () => {
      const keyPair = ECPair.makeRandom({ compressed: false });
      const wif = keyPair.toWIF();
      const imported = ECPair.fromWIF(wif);
      assert.strictEqual(imported.compressed, false);
    });

    it('should throw on missing private key for WIF', () => {
      const keyPair = ECPair.fromPublicKey(ECPair.makeRandom().publicKey);
      assert.throws(() => {
        keyPair.toWIF();
      }, /Missing private key/);
    });
  });

  describe('Signing and Verification', () => {
    const messageHash = createHash('sha256')
      .update(Buffer.from('test message'))
      .digest();

    it('should sign and verify', () => {
      const keyPair = ECPair.makeRandom();
      const signature = keyPair.sign(messageHash);
      const isValid = keyPair.verify(messageHash, signature);
      assert.strictEqual(isValid, true);
    });

    it('should fail on invalid signature', () => {
      const keyPair = ECPair.makeRandom();
      const invalidSig = Buffer.alloc(64, 1);
      const isValid = keyPair.verify(messageHash, invalidSig);
      assert.strictEqual(isValid, false);
    });

    it('should throw when signing without private key', () => {
      const keyPair = ECPair.fromPublicKey(ECPair.makeRandom().publicKey);
      assert.throws(() => {
        keyPair.sign(messageHash);
      }, /Missing private key/);
    });

    it('should handle Schnorr signatures when supported', () => {
      const keyPair = ECPair.makeRandom();
      if (tinysecp.signSchnorr) {
        const signature = keyPair.signSchnorr(messageHash);
        const isValid = keyPair.verifySchnorr(messageHash, signature);
        assert.strictEqual(isValid, true);
      } else {
        assert.throws(() => {
          keyPair.signSchnorr(messageHash);
        }, /signSchnorr not supported/);
      }
    });
  });

  describe('Tweaking', () => {
    it('should tweak private key', () => {
      const keyPair = ECPair.makeRandom();
      const tweak = Buffer.alloc(32, 2);
      const tweaked = keyPair.tweak(tweak);
      assert.strictEqual(Buffer.isBuffer(tweaked.privateKey), true);
      assert.strictEqual(Buffer.isBuffer(tweaked.publicKey), true);
    });

    it('should tweak public key', () => {
      const keyPair = ECPair.fromPublicKey(ECPair.makeRandom().publicKey);
      const tweak = Buffer.alloc(32, 2);
      const tweaked = keyPair.tweak(tweak);
      assert.strictEqual(Buffer.isBuffer(tweaked.publicKey), true);
    });
  });

  describe('isPoint', () => {
    it('should validate valid points', () => {
      const keyPair = ECPair.makeRandom();
      assert.strictEqual(ECPair.isPoint(keyPair.publicKey), true);
    });

    it('should reject invalid points', () => {
      const notAPoint = Buffer.alloc(33, 1);
      assert.strictEqual(ECPair.isPoint(notAPoint), false);
    });
  });
});
