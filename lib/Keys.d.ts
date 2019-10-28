import { KeyPair } from 'libsodium-wrappers';
export declare type PublicKey = Uint8Array;
export declare type Signature = Uint8Array;
export interface KeyMaterial {
    readonly identityKeyPair: KeyPair;
    signedPrekeyPair: KeyPair;
    oneTimePrekeyPairs: KeyPair[];
}
export declare class PublicKeyMaterial {
    readonly identityKey: PublicKey;
    readonly signedPrekey: PublicKey;
    readonly prekeySignature: Signature;
    oneTimePrekeyPairs: PublicKey[];
    prekeyBundle(): PrekeyBundle;
    constructor(identityKey: PublicKey, signedPrekey: PublicKey, prekeySignature: Signature, oneTimePrekeyPairs: PublicKey[]);
}
export interface PrekeyBundle {
    readonly identityKey: PublicKey;
    readonly signedPrekey: PublicKey;
    readonly prekeySignature: Signature;
    readonly oneTimePrekey?: PublicKey;
}
//# sourceMappingURL=Keys.d.ts.map