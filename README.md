# csharp-lib-crypto
C# implementation of the unified crypto primitives for Waves Platform

## Include
```csharp
using csharp_lib_crypto;
```

## Seed generation

```csharp
var crypto = new WavesCrypto();
string seed = crypto.RandomSeed();
```
## Keys and address

### publicKey
```csharp
var crypto = new WavesCrypto();
string seed = "uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine"
var publicKey = crypto.PublicKey(seed);
int nonce = 0;
var publicKey = crypto.PublicKey(seed, nonce);
```
### privateKey
```csharp
var crypto = new WavesCrypto();
string seed = "uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine"
var privateKey = crypto.PrivateKey(seed);
int nonce = 0;
var privateKey = crypto.PrivateKey(seed, nonce);
```

### keyPair
```csharp
var crypto = new WavesCrypto();
string seed = "uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine"
var keyPair = new KeyPair(seed);
```
### address
```csharp
var crypto = new WavesCrypto();
string seed = "uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine"
var address = crypto.Address(seed, WavesChainId.MAIN_NET_CHAIN_ID); //or WavesChainId.TEST_NET_CHAIN_ID
```
## Signatures
### signBytes
```csharp
            var crypto = new WavesCrypto();
            var seed = "uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine";
            var bytes = new byte[] { 117, 110, 99, 108, 101};
            
            var sign = crypto.SignBytes(bytes, seed);
            
            var privateKey = "8bg5KM2n5kKQE6bVZssvwMEivc6ctyKahfGLkQfszZfY";
            var sign2 = crypto.SignBytesWithPrivateKey(bytes, privateKey);
```
### verifySignature
```csharp
var crypto = new WavesCrypto();
var seed = "uncle push human bus echo drastic garden joke sand warfare sentence fossil title color combine";
var bytes = new byte[] { 117, 110, 99, 108, 101};
var sign = crypto.SignBytes(bytes, seed);
crypto.VerifySignature(publicKeyInit, bytes, sign)
```

## Hashing
## blake2b
```csharp
var crypto = new WavesCrypto();
var bytes = new byte[] { 117, 110, 99, 108, 101};
crypto.Blake2b(bytes);
```

## keccak
```csharp
var crypto = new WavesCrypto();
var bytes = new byte[] { 117, 110, 99, 108, 101};
crypto.Keccak(bytes);
```

## sha256
```csharp
var crypto = new WavesCrypto();
var bytes = new byte[] { 117, 110, 99, 108, 101};
crypto.Sha256(bytes);
```

## Random
### randomBytes
```csharp
var crypto = new WavesCrypto();
var size = 5;
var bytes = crypto.RandomBytes(size);
```
## Base encoding\decoding
```csharp
var crypto = new WavesCrypto();
var bytes = crypto.RandomBytes(32);

var base16String = crypto.Base16Encode(bytes);
var bytesFromBase16 = crypto.Base16Decode(base58String);

var base58String = crypto.Base58Encode(bytes);
var bytesFromBase58 = crypto.Base58Decode(base58String);

var base64String = crypto.Base64Encode(bytes);
var bytesFromBase64 = crypto.Base64Decode(base58String);
```

## Messaging
``` - sharedKey```

## Utils

### stringToBytes
```csharp
var crypto = new WavesCrypto();
var bytes = new byte[] { 6, 7, 8, 4 };
var stringFromBytes = crypto.BytesToString(bytes);
```
### bytesToString
```csharp
var crypto = new WavesCrypto();
var bytes = "WAVES";
var bytesFromString = crypto.StringToBytes(stringFromBytes);
```

## Constants
```csharp
    static class WavesCryptoConstants
    {
        public const int PUBLIC_KEY_LENGTH = 32;
        public const int PRIVATE_KEY_LENGTH = 32;
        public const int SIGNATURE_LENGTH = 64;
    }

    public enum WavesChainId
    {
        MAIN_NET_CHAIN_ID = 87,
        TEST_NET_CHAIN_ID = 84,
    }
```
