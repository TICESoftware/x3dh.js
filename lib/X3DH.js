"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const libsodium_wrappers_1 = require("libsodium-wrappers");
const Keys_1 = require("./Keys");
const hkdf_js_1 = require("hkdf.js");
class X3DH {
    constructor(identityKeyPair, signedPrekeyPair, oneTimePrekeyPairs) {
        this.keyMaterial = {
            identityKeyPair: identityKeyPair,
            signedPrekeyPair: signedPrekeyPair,
            oneTimePrekeyPairs: oneTimePrekeyPairs
        };
    }
    signedPrekeyPair() {
        return this.keyMaterial.signedPrekeyPair;
    }
    static init() {
        return __awaiter(this, void 0, void 0, function* () {
            yield libsodium_wrappers_1.ready;
            const identityKeyPair = libsodium_wrappers_1.crypto_kx_keypair();
            const signedPrekeyPair = libsodium_wrappers_1.crypto_kx_keypair();
            return new X3DH(identityKeyPair, signedPrekeyPair, []);
        });
    }
    createPrekeyBundle(oneTimePrekeysCount, renewSignedPrekey, prekeySigner) {
        return __awaiter(this, void 0, void 0, function* () {
            yield libsodium_wrappers_1.ready;
            if (renewSignedPrekey) {
                this.keyMaterial.signedPrekeyPair = libsodium_wrappers_1.crypto_kx_keypair();
            }
            let oneTimePrekeyPairs = [];
            for (let i = 0; i < oneTimePrekeysCount; i++) {
                oneTimePrekeyPairs.push(libsodium_wrappers_1.crypto_kx_keypair());
            }
            this.keyMaterial.oneTimePrekeyPairs = oneTimePrekeyPairs;
            const oneTimePrekeyPublicKeys = oneTimePrekeyPairs.map(x => x.publicKey);
            const prekeySignature = prekeySigner(this.keyMaterial.signedPrekeyPair.publicKey);
            return new Keys_1.PublicKeyMaterial(this.keyMaterial.identityKeyPair.publicKey, this.keyMaterial.signedPrekeyPair.publicKey, prekeySignature, oneTimePrekeyPublicKeys);
        });
    }
    initiateKeyAgreement(remotePrekeyBundle, prekeySignatureVerifier, info) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!prekeySignatureVerifier(remotePrekeyBundle.prekeySignature)) {
                throw Error("Verification of prekey signature failed." /* invalidPrekeySignature */);
            }
            yield libsodium_wrappers_1.ready;
            const ephemeralKeyPair = libsodium_wrappers_1.crypto_kx_keypair();
            const dh1 = { ownKeyPair: this.keyMaterial.identityKeyPair, remotePublicKey: remotePrekeyBundle.signedPrekey };
            const dh2 = { ownKeyPair: ephemeralKeyPair, remotePublicKey: remotePrekeyBundle.identityKey };
            const dh3 = { ownKeyPair: ephemeralKeyPair, remotePublicKey: remotePrekeyBundle.signedPrekey };
            const dh4 = remotePrekeyBundle.oneTimePrekey ? { ownKeyPair: ephemeralKeyPair, remotePublicKey: remotePrekeyBundle.oneTimePrekey } : undefined;
            const sk = yield this.sharedSecret(Side.initiating, info, dh1, dh2, dh3, dh4);
            let ad = new Uint8Array(2 * libsodium_wrappers_1.crypto_auth_KEYBYTES);
            ad.set(this.keyMaterial.signedPrekeyPair.publicKey);
            ad.set(remotePrekeyBundle.identityKey, libsodium_wrappers_1.crypto_auth_KEYBYTES);
            return {
                sharedSecret: sk,
                associatedData: ad,
                identityPublicKey: this.keyMaterial.identityKeyPair.publicKey,
                ephemeralPublicKey: ephemeralKeyPair.publicKey,
                usedOneTimePrekey: remotePrekeyBundle.oneTimePrekey
            };
        });
    }
    sharedSecretFromKeyAgreement(info, remoteIdentityPublicKey, remoteEphemeralPublicKey, usedOneTimePrekey) {
        return __awaiter(this, void 0, void 0, function* () {
            const dh1 = { ownKeyPair: this.keyMaterial.signedPrekeyPair, remotePublicKey: remoteIdentityPublicKey };
            const dh2 = { ownKeyPair: this.keyMaterial.identityKeyPair, remotePublicKey: remoteEphemeralPublicKey };
            const dh3 = { ownKeyPair: this.keyMaterial.signedPrekeyPair, remotePublicKey: remoteEphemeralPublicKey };
            let dh4 = undefined;
            if (usedOneTimePrekey) {
                const oneTimePrekeyPairIndex = this.keyMaterial.oneTimePrekeyPairs.findIndex(value => value.publicKey.join() == usedOneTimePrekey.join());
                if (oneTimePrekeyPairIndex == -1) {
                    throw Error("Invalid one-time prekey used for key agreement." /* invalidOneTimePrekey */);
                }
                const oneTimePrekeyPair = this.keyMaterial.oneTimePrekeyPairs.splice(oneTimePrekeyPairIndex, 1)[0];
                dh4 = { ownKeyPair: oneTimePrekeyPair, remotePublicKey: remoteEphemeralPublicKey };
            }
            return yield this.sharedSecret(Side.responding, info, dh1, dh2, dh3, dh4);
        });
    }
    sharedSecret(side, info, DH1, DH2, DH3, DH4) {
        return __awaiter(this, void 0, void 0, function* () {
            yield libsodium_wrappers_1.ready;
            const dh1 = yield this.sessionKeyPair(DH1.ownKeyPair.publicKey, DH1.ownKeyPair.privateKey, DH1.remotePublicKey, side);
            const dh2 = yield this.sessionKeyPair(DH2.ownKeyPair.publicKey, DH2.ownKeyPair.privateKey, DH2.remotePublicKey, side);
            const dh3 = yield this.sessionKeyPair(DH3.ownKeyPair.publicKey, DH3.ownKeyPair.privateKey, DH3.remotePublicKey, side);
            let dh4 = undefined;
            if (DH4) {
                dh4 = yield this.sessionKeyPair(DH4.ownKeyPair.publicKey, DH4.ownKeyPair.privateKey, DH4.remotePublicKey, side);
            }
            let input = new Uint8Array(32 + (dh4 ? 4 * libsodium_wrappers_1.crypto_kx_SESSIONKEYBYTES : 3 * libsodium_wrappers_1.crypto_kx_SESSIONKEYBYTES));
            input.fill(255, 0, 32);
            input.set(side == Side.initiating ? dh1.sharedRx : dh1.sharedTx, 32);
            input.set(side == Side.initiating ? dh2.sharedRx : dh2.sharedTx, 32 + libsodium_wrappers_1.crypto_kx_SESSIONKEYBYTES);
            input.set(side == Side.initiating ? dh3.sharedRx : dh3.sharedTx, 32 + 2 * libsodium_wrappers_1.crypto_kx_SESSIONKEYBYTES);
            if (dh4) {
                input.set(side == Side.initiating ? dh4.sharedRx : dh4.sharedTx, 32 + 3 * libsodium_wrappers_1.crypto_kx_SESSIONKEYBYTES);
            }
            const salt = new Uint8Array(32).fill(0);
            return hkdf_js_1.deriveHKDFKey(input, 32, salt, info);
        });
    }
    sessionKeyPair(publicKey, secretKey, otherPublicKey, side) {
        return __awaiter(this, void 0, void 0, function* () {
            yield libsodium_wrappers_1.ready;
            if (side == Side.initiating) {
                return libsodium_wrappers_1.crypto_kx_client_session_keys(publicKey, secretKey, otherPublicKey);
            }
            else {
                return libsodium_wrappers_1.crypto_kx_server_session_keys(publicKey, secretKey, otherPublicKey);
            }
        });
    }
}
exports.X3DH = X3DH;
var Side;
(function (Side) {
    Side[Side["initiating"] = 0] = "initiating";
    Side[Side["responding"] = 1] = "responding";
})(Side || (Side = {}));
//# sourceMappingURL=X3DH.js.map