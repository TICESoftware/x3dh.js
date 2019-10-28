"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class PublicKeyMaterial {
    constructor(identityKey, signedPrekey, prekeySignature, oneTimePrekeyPairs) {
        this.identityKey = identityKey;
        this.signedPrekey = signedPrekey;
        this.prekeySignature = prekeySignature;
        this.oneTimePrekeyPairs = oneTimePrekeyPairs;
    }
    prekeyBundle() {
        return {
            identityKey: this.identityKey,
            signedPrekey: this.signedPrekey,
            prekeySignature: this.prekeySignature,
            oneTimePrekey: this.oneTimePrekeyPairs.pop()
        };
    }
}
exports.PublicKeyMaterial = PublicKeyMaterial;
//# sourceMappingURL=Keys.js.map