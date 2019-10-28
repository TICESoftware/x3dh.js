import { KeyPair } from 'libsodium-wrappers';
import { KeyMaterial, PublicKey, Signature, PublicKeyMaterial, PrekeyBundle } from './Keys';
declare type Bytes = Uint8Array;
declare type PrekeySigner = (publicKey: PublicKey) => Signature;
declare type PrekeySignatureVerifier = (signature: Signature) => boolean;
export declare class X3DH {
    keyMaterial: KeyMaterial;
    signedPrekeyPair(): KeyPair;
    static init(): Promise<X3DH>;
    constructor(identityKeyPair: KeyPair, signedPrekeyPair: KeyPair, oneTimePrekeyPairs: KeyPair[]);
    createPrekeyBundle(oneTimePrekeysCount: number, renewSignedPrekey: boolean, prekeySigner: PrekeySigner): Promise<PublicKeyMaterial>;
    initiateKeyAgreement(remotePrekeyBundle: PrekeyBundle, prekeySignatureVerifier: PrekeySignatureVerifier, info: string): Promise<KeyAgreementInitiation>;
    sharedSecretFromKeyAgreement(info: string, remoteIdentityPublicKey: PublicKey, remoteEphemeralPublicKey: PublicKey, usedOneTimePrekey?: PublicKey): Promise<Bytes>;
    private sharedSecret;
    private sessionKeyPair;
}
interface KeyAgreementInitiation {
    readonly sharedSecret: Bytes;
    readonly associatedData: Bytes;
    readonly identityPublicKey: PublicKey;
    readonly ephemeralPublicKey: PublicKey;
    readonly usedOneTimePrekey?: PublicKey;
}
export declare const enum X3DHError {
    keyGenerationFailed = "Generation of key pair failed.",
    invalidPrekeySignature = "Verification of prekey signature failed.",
    invalidOneTimePrekey = "Invalid one-time prekey used for key agreement."
}
export {};
//# sourceMappingURL=X3DH.d.ts.map