import {X3DH, X3DHError} from './X3DH';
import { ready as sodiumReady, from_hex, to_hex, crypto_auth_BYTES, crypto_auth_KEYBYTES, crypto_auth } from "libsodium-wrappers";

test('keyAgreementWithOneTimePrekey',async () => {
    await sodiumReady;
    const info = "testKeyAgreement";

    const bob = await X3DH.init();
    let bobPublicKeyMaterial = await bob.createPrekeyBundle(2, false, x => x);
    const bobPrekeyBundle = bobPublicKeyMaterial.prekeyBundle();

    const alice = await X3DH.init();
    // [Alice fetches Bob's prekey bundle]
    const keyAgreementInitiation = await alice.initiateKeyAgreement(bobPrekeyBundle, x => true, info);
    expect(keyAgreementInitiation.usedOneTimePrekey).toBeDefined();

    // [Alice sends identity key, ephemeral key and used one-time prekey to Bob]
    const sharedSecret = await bob.sharedSecretFromKeyAgreement(info, keyAgreementInitiation.identityPublicKey, keyAgreementInitiation.ephemeralPublicKey, keyAgreementInitiation.usedOneTimePrekey);
    expect(sharedSecret).toEqual(keyAgreementInitiation.sharedSecret);
});

test('keyAgreementWithoutOneTimePrekey', async () => {
    await sodiumReady;
    const info = "testKeyAgreement";

    const bob = await X3DH.init();
    let bobPublicKeyMaterial = await bob.createPrekeyBundle(0, false, x => x);
    const bobPrekeyBundle = bobPublicKeyMaterial.prekeyBundle();

    const alice = await X3DH.init();
    // [Alice fetches Bob's prekey bundle]
    const keyAgreementInitiation = await alice.initiateKeyAgreement(bobPrekeyBundle, () => true, info);
    expect(keyAgreementInitiation.usedOneTimePrekey).toBeUndefined();

    // [Alice sends identity key, ephemeral key and used one-time prekey to Bob]
    const sharedSecret = await bob.sharedSecretFromKeyAgreement(info, keyAgreementInitiation.identityPublicKey, keyAgreementInitiation.ephemeralPublicKey, keyAgreementInitiation.usedOneTimePrekey);
    expect(sharedSecret).toEqual(keyAgreementInitiation.sharedSecret);
});

test('keyAgreementInvalidSignature', async () => {
    await sodiumReady;
    const info = "testKeyAgreement";

    const bob = await X3DH.init();
    let bobPublicKeyMaterial = await bob.createPrekeyBundle(2, false, x => x);
    const bobPrekeyBundle = bobPublicKeyMaterial.prekeyBundle();

    const alice = await X3DH.init();
    // [Alice fetches Bob's prekey bundle]
    try {
        const keyAgreementInitiation = await alice.initiateKeyAgreement(bobPrekeyBundle, () => false, info);
    } catch(error: any) {
        expect(error.message).toMatch(X3DHError.invalidPrekeySignature);
    }
});
