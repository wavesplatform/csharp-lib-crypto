namespace csharp_lib_crypto
{
    using PublicKey = System.String;
    using PrivateKey = System.String;
    using Seed = System.String;
    using Address = System.String;

    public interface IKeyPair
    {
        PublicKey PublicKey { get; }
        PrivateKey PrivateKey { get; }
    }

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

    public interface IWavesCrypto
    {

        byte[] Blake2b(byte[] input);
        byte[] Keccak(byte[] input);
        byte[] Sha256(byte[] input);

        string Base58Encode(byte[] input);
        byte[] Base58Decode(string input);
        string Base64Encode(byte[] input);
        byte[] Base64Decode(string input);
        string Base16Encode(byte[] input);
        byte[] Base16Decode(string input);

        IKeyPair KeyPair(Seed seed);
        PublicKey PublicKey(Seed seed);
        PrivateKey PrivateKey(Seed seed);

        Address AddressFromPublicKey(PublicKey publicKey, WavesChainId? chainId = null);
        Address Address(Seed seed, WavesChainId? chainId = null);

        Seed RandomSeed();
        byte[] RandomBytes(int size);
        byte[] StringToBytes(string input);
        string BytesToString(byte[] input);

        byte[] SignBytesWithPrivateKey(byte[] bytes, PrivateKey privateKey);
        byte[] SignBytes(byte[] bytes, Seed seed);

        bool VerifySignature(PublicKey publicKey, byte[] bytes, byte[] signature);
        bool VerifyPublicKey(PublicKey publicKey);
        bool VerifyAddress(Address address, WavesChainId? chainId, PublicKey publicKey);

        byte[] SharedKey(byte[] privateKeyFrom, byte[] publicKeyTo, string prefix);
        string MessageDecrypt(byte[] sharedKey, byte[] encryptedMessage, string prefix);
        byte[] MessageEncrypt(byte[] sharedKey, string message, string prefix);
    }
}
