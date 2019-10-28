import { KeyPair } from 'libsodium-wrappers';

export type PublicKey = Uint8Array;
export type Signature = Uint8Array;

export interface KeyMaterial {
    readonly identityKeyPair: KeyPair;
    signedPrekeyPair: KeyPair;
    oneTimePrekeyPairs: KeyPair[];
}

export class PublicKeyMaterial {
    readonly identityKey: PublicKey;
    readonly signedPrekey: PublicKey;
    readonly prekeySignature: Signature;
    oneTimePrekeyPairs: PublicKey[];

    prekeyBundle(): PrekeyBundle {
        return {
            identityKey: this.identityKey,
            signedPrekey: this.signedPrekey,
            prekeySignature: this.prekeySignature,
            oneTimePrekey: this.oneTimePrekeyPairs.pop()
        }
    }

    constructor(identityKey: PublicKey, signedPrekey: PublicKey, prekeySignature: Signature, oneTimePrekeyPairs: PublicKey[]) {
        this.identityKey = identityKey;
        this.signedPrekey = signedPrekey;
        this.prekeySignature = prekeySignature;
        this.oneTimePrekeyPairs = oneTimePrekeyPairs;
    }
}

export interface PrekeyBundle {
    readonly identityKey: PublicKey;
    readonly signedPrekey: PublicKey;
    readonly prekeySignature: Signature;
    readonly oneTimePrekey?: PublicKey;
}
