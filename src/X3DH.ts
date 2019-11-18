import {
    ready as sodiumReady,
    KeyPair,
    crypto_auth_KEYBYTES,
    crypto_kx_keypair,
    crypto_kx_server_session_keys,
    crypto_kx_client_session_keys,
    CryptoKX,
    crypto_kx_SESSIONKEYBYTES
} from 'libsodium-wrappers';
import { KeyMaterial, PublicKey, Signature, PublicKeyMaterial, PrekeyBundle } from './Keys';
import { deriveHKDFKey } from "hkdf.js";

type Bytes = Uint8Array;
type PrekeySigner = (publicKey: PublicKey) => Signature;
type PrekeySignatureVerifier = (signature: Signature) => boolean;

export class X3DH {
    keyMaterial: KeyMaterial;
    signedPrekeyPair(): KeyPair {
        return this.keyMaterial.signedPrekeyPair
    }

    static async init(): Promise<X3DH> {
        await sodiumReady;
        const identityKeyPair = crypto_kx_keypair();
        const signedPrekeyPair = crypto_kx_keypair();

        return new X3DH(identityKeyPair, signedPrekeyPair, []);
    }

    constructor(identityKeyPair: KeyPair, signedPrekeyPair: KeyPair, oneTimePrekeyPairs: KeyPair[]) {
        this.keyMaterial = {
            identityKeyPair: identityKeyPair,
            signedPrekeyPair: signedPrekeyPair,
            oneTimePrekeyPairs: oneTimePrekeyPairs
        }
    }

    async createPrekeyBundle(oneTimePrekeysCount: number, renewSignedPrekey: boolean, prekeySigner: PrekeySigner): Promise<PublicKeyMaterial> {
        await sodiumReady;
        if (renewSignedPrekey) {
            this.keyMaterial.signedPrekeyPair = crypto_kx_keypair();
        }

        let oneTimePrekeyPairs: KeyPair[] = [];
        for (let i = 0; i < oneTimePrekeysCount; i++) {
            oneTimePrekeyPairs.push(crypto_kx_keypair());
        }
        this.keyMaterial.oneTimePrekeyPairs = oneTimePrekeyPairs;
        const oneTimePrekeyPublicKeys = oneTimePrekeyPairs.map(x => x.publicKey);

        const prekeySignature = prekeySigner(this.keyMaterial.signedPrekeyPair.publicKey);
        return new PublicKeyMaterial(this.keyMaterial.identityKeyPair.publicKey, this.keyMaterial.signedPrekeyPair.publicKey, prekeySignature, oneTimePrekeyPublicKeys)
    }

    async initiateKeyAgreement(remotePrekeyBundle: PrekeyBundle, prekeySignatureVerifier: PrekeySignatureVerifier, info: string): Promise<KeyAgreementInitiation> {
        if (!prekeySignatureVerifier(remotePrekeyBundle.prekeySignature)) {
            throw Error(X3DHError.invalidPrekeySignature)
        }
        await sodiumReady;
        const ephemeralKeyPair = crypto_kx_keypair();

        const dh1: DH = {ownKeyPair: this.keyMaterial.identityKeyPair, remotePublicKey: remotePrekeyBundle.signedPrekey};
        const dh2: DH = {ownKeyPair: ephemeralKeyPair, remotePublicKey: remotePrekeyBundle.identityKey};
        const dh3: DH = {ownKeyPair: ephemeralKeyPair, remotePublicKey: remotePrekeyBundle.signedPrekey};
        const dh4: DH | undefined = remotePrekeyBundle.oneTimePrekey ? {ownKeyPair: ephemeralKeyPair, remotePublicKey: remotePrekeyBundle.oneTimePrekey} : undefined;
        const sk = await this.sharedSecret(Side.initiating, info, dh1, dh2, dh3, dh4);

        let ad = new Uint8Array(2*crypto_auth_KEYBYTES);
        ad.set(this.keyMaterial.signedPrekeyPair.publicKey);
        ad.set(remotePrekeyBundle.identityKey, crypto_auth_KEYBYTES);

        return {
            sharedSecret: sk,
            associatedData: ad,
            identityPublicKey: this.keyMaterial.identityKeyPair.publicKey,
            ephemeralPublicKey: ephemeralKeyPair.publicKey,
            usedOneTimePrekey: remotePrekeyBundle.oneTimePrekey
        }
    }

    async sharedSecretFromKeyAgreement(info: string, remoteIdentityPublicKey: PublicKey, remoteEphemeralPublicKey: PublicKey, usedOneTimePrekey?: PublicKey): Promise<Bytes> {
        const dh1: DH = {ownKeyPair: this.keyMaterial.signedPrekeyPair, remotePublicKey: remoteIdentityPublicKey};
        const dh2: DH = {ownKeyPair: this.keyMaterial.identityKeyPair, remotePublicKey: remoteEphemeralPublicKey};
        const dh3: DH = {ownKeyPair: this.keyMaterial.signedPrekeyPair, remotePublicKey: remoteEphemeralPublicKey};
        let dh4: DH | undefined = undefined;
        if (usedOneTimePrekey) {
            const oneTimePrekeyPairIndex = this.keyMaterial.oneTimePrekeyPairs.findIndex( value => value.publicKey.join() == usedOneTimePrekey.join());
            if (oneTimePrekeyPairIndex == -1) {
                throw Error(X3DHError.invalidOneTimePrekey);
            }
            const oneTimePrekeyPair = this.keyMaterial.oneTimePrekeyPairs.splice(oneTimePrekeyPairIndex, 1)[0];
            dh4 = {ownKeyPair: oneTimePrekeyPair, remotePublicKey: remoteEphemeralPublicKey};
        }

        return await this.sharedSecret(Side.responding, info, dh1, dh2, dh3, dh4)
    }

    private async sharedSecret(side: Side, info: string, DH1: DH, DH2: DH, DH3: DH, DH4?: DH): Promise<Bytes> {
        await sodiumReady;
        const dh1 = await this.sessionKeyPair(DH1.ownKeyPair.publicKey, DH1.ownKeyPair.privateKey, DH1.remotePublicKey, side);
        const dh2 = await this.sessionKeyPair(DH2.ownKeyPair.publicKey, DH2.ownKeyPair.privateKey, DH2.remotePublicKey, side);
        const dh3 = await this.sessionKeyPair(DH3.ownKeyPair.publicKey, DH3.ownKeyPair.privateKey, DH3.remotePublicKey, side);
        let dh4: CryptoKX | undefined = undefined;
        if (DH4) {
            dh4 = await this.sessionKeyPair(DH4.ownKeyPair.publicKey, DH4.ownKeyPair.privateKey, DH4.remotePublicKey, side);
        }

        let input = new Uint8Array(32 + (dh4 ? 4 * crypto_kx_SESSIONKEYBYTES: 3 * crypto_kx_SESSIONKEYBYTES));
        input.fill(255, 0, 32);
        input.set(side == Side.initiating ? dh1.sharedRx : dh1.sharedTx, 32);
        input.set(side == Side.initiating ? dh2.sharedRx : dh2.sharedTx, 32 + crypto_kx_SESSIONKEYBYTES);
        input.set(side == Side.initiating ? dh3.sharedRx : dh3.sharedTx, 32 + 2 * crypto_kx_SESSIONKEYBYTES);
        if (dh4) {
            input.set(side == Side.initiating ? dh4.sharedRx : dh4.sharedTx, 32 + 3 * crypto_kx_SESSIONKEYBYTES);
        }

        const salt = new Uint8Array(32).fill(0);
        return deriveHKDFKey(input, 32, salt, info);
    }

    private async sessionKeyPair(publicKey: PublicKey, secretKey: Bytes, otherPublicKey: PublicKey, side: Side): Promise<CryptoKX> {
        await sodiumReady;
        if (side == Side.initiating) {
            return crypto_kx_client_session_keys(publicKey, secretKey, otherPublicKey);
        } else {
            return crypto_kx_server_session_keys(publicKey, secretKey, otherPublicKey);
        }
    }
}

interface DH {
    readonly ownKeyPair: KeyPair;
    readonly remotePublicKey: PublicKey;
}

interface KeyAgreementInitiation {
    readonly sharedSecret: Bytes;
    readonly associatedData: Bytes;
    readonly identityPublicKey: PublicKey;
    readonly ephemeralPublicKey: PublicKey;
    readonly usedOneTimePrekey?: PublicKey;
}

enum Side {
    initiating,
    responding
}

export const enum X3DHError {
    keyGenerationFailed = 'Generation of key pair failed.',
    invalidPrekeySignature = 'Verification of prekey signature failed.',
    invalidOneTimePrekey = 'Invalid one-time prekey used for key agreement.'
}
