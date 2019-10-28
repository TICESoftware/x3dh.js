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
const X3DH_1 = require("./X3DH");
const libsodium_wrappers_1 = require("libsodium-wrappers");
test('keyAgreementWithOneTimePrekey', () => __awaiter(void 0, void 0, void 0, function* () {
    yield libsodium_wrappers_1.ready;
    const info = "testKeyAgreement";
    const bob = yield X3DH_1.X3DH.init();
    let bobPublicKeyMaterial = yield bob.createPrekeyBundle(2, false, x => x);
    const bobPrekeyBundle = bobPublicKeyMaterial.prekeyBundle();
    const alice = yield X3DH_1.X3DH.init();
    // [Alice fetches Bob's prekey bundle]
    const keyAgreementInitiation = yield alice.initiateKeyAgreement(bobPrekeyBundle, x => true, info);
    expect(keyAgreementInitiation.usedOneTimePrekey).toBeDefined();
    // [Alice sends identity key, ephemeral key and used one-time prekey to Bob]
    const sharedSecret = yield bob.sharedSecretFromKeyAgreement(info, keyAgreementInitiation.identityPublicKey, keyAgreementInitiation.ephemeralPublicKey, keyAgreementInitiation.usedOneTimePrekey);
    expect(sharedSecret).toEqual(keyAgreementInitiation.sharedSecret);
}));
test('keyAgreementWithoutOneTimePrekey', () => __awaiter(void 0, void 0, void 0, function* () {
    yield libsodium_wrappers_1.ready;
    const info = "testKeyAgreement";
    const bob = yield X3DH_1.X3DH.init();
    let bobPublicKeyMaterial = yield bob.createPrekeyBundle(0, false, x => x);
    const bobPrekeyBundle = bobPublicKeyMaterial.prekeyBundle();
    const alice = yield X3DH_1.X3DH.init();
    // [Alice fetches Bob's prekey bundle]
    const keyAgreementInitiation = yield alice.initiateKeyAgreement(bobPrekeyBundle, () => true, info);
    expect(keyAgreementInitiation.usedOneTimePrekey).toBeUndefined();
    // [Alice sends identity key, ephemeral key and used one-time prekey to Bob]
    const sharedSecret = yield bob.sharedSecretFromKeyAgreement(info, keyAgreementInitiation.identityPublicKey, keyAgreementInitiation.ephemeralPublicKey, keyAgreementInitiation.usedOneTimePrekey);
    expect(sharedSecret).toEqual(keyAgreementInitiation.sharedSecret);
}));
test('keyAgreementInvalidSignature', () => __awaiter(void 0, void 0, void 0, function* () {
    yield libsodium_wrappers_1.ready;
    const info = "testKeyAgreement";
    const bob = yield X3DH_1.X3DH.init();
    let bobPublicKeyMaterial = yield bob.createPrekeyBundle(2, false, x => x);
    const bobPrekeyBundle = bobPublicKeyMaterial.prekeyBundle();
    const alice = yield X3DH_1.X3DH.init();
    // [Alice fetches Bob's prekey bundle]
    try {
        const keyAgreementInitiation = yield alice.initiateKeyAgreement(bobPrekeyBundle, () => false, info);
    }
    catch (error) {
        expect(error.message).toMatch("Verification of prekey signature failed." /* invalidPrekeySignature */);
    }
}));
//# sourceMappingURL=X3DH.test.js.map