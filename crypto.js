"use strict";

// This file contains all the critical code
// It MUST be readable to easily spot flaws

// Namespace for all of these functions
var CRYPTO = {
    // --- KEX: ECDH ---
    KEX: {
        // Singleton instance for curve25519
        _ec: new elliptic.ec('curve25519'),
        // The ECDH key is saved here to easily access it
        _key: null,
        // Generate a brand new ECDH keypair
        genKeyPair: function () {
            this._key = this._ec.genKeyPair();
            return [this._key.getPublic('hex'), this._key.getPrivate('hex')];
        },
        // Restore an existing ECDH keypair
        restoreKey: function (priv) {
            this._key = this._ec.keyFromPrivate(priv);
        },
        // Key derivation function, from alice's public key
        derive: function (alice) {
            let other;
            try {
                other = this._ec.keyFromPublic(alice, 'hex').getPublic();
            } catch(e) {
                alert('Invalid key');
                throw new Error('Invalid key');
            }

            return this._key.derive(other).toString(16);
        }
    },

    // --- AE: AES-256-GCM ---
    AE: {
        // Get AES instance
        getAES: function (hexkey) {
            const key = sjcl.codec.hex.toBits(hexkey);
            return new sjcl.cipher.aes(key);
        },
        // sjcl operates with words (4 bytes), and 96 bits is kind of standard
        _IV_WORDS: (96 / 8) / 4,
        // Generate IV
        _genIV: function () {
            // sjcl's PRNG works with "words", 4 bytes each
            return sjcl.random.randomWords(this._IV_WORDS);
        },
        // Encrypt function, receives string, returns in base64
        encrypt: function (aes, contents) {
            const raw = sjcl.codec.utf8String.toBits(contents);
            const iv = this._genIV();
            const enc = sjcl.mode.gcm.encrypt(aes, raw, iv);
            const both = iv.concat(enc);
            return sjcl.codec.base64.fromBits(both);
        },
        // Decrypt function, receives base64, returns string
        decrypt: function (aes, encoded) {
            let both;
            try {
                both = sjcl.codec.base64.toBits(encoded);
            } catch(e) {
                alert('Input is not base64');
                throw new Error('Input is not base64');
            }

            const iv = both.slice(0, this._IV_WORDS);
            const enc = both.slice(this._IV_WORDS);

            let dec;
            try {
                dec = sjcl.mode.gcm.decrypt(aes, enc, iv);
            } catch(e) {
                alert('Error decrypting');
                throw new Error('Error decrypting');
            }

            return sjcl.codec.utf8String.fromBits(dec);
        }
    }
};
