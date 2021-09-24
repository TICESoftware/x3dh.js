# X3DH

This package implements the [X3DH](https://signal.org/docs/specifications/x3dh/) key agreement protocol in TypeScript. The cryptographic operations are provided by [libsodium](https://github.com/jedisct1/libsodium) entirely.

## Installation

```bash
$ yarn add x3dh
or
$ npm i --save x3dh
```

## Usage

Alice needs to retrieve some public keys from Bob that he has made public previously. She then calculates a shared secret and sends some information to Bob so that he can calculcate the shared secret on his side as well.

```typescript
import {X3DH} from "./X3DH";

const prekeySigner = // ... Signing the key is not part of this library
const prekeySignatureVerifier = // ... and neither is verification

const bob = await X3DH.init();
const bobPrekeyBundle = await bob.createPrekeyBundle(100, false, prekeySigner);

const alice = await X3DH.init();
// [Alice fetches bob's prekey bundle]
const keyAgreementInitiation = await alice.initiateKeyAgreement(bobPrekeyBundle, prekeySignatureVerifier, "Example");

// [Alice sends identity key, ephemeral key and used one-time prekey to bob]
const sharedSecret = await bob.sharedSecretFromKeyAgreement("Example", identityKey, ephemeralKey, usedOneTimePrekey);
```
