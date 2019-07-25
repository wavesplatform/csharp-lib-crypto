using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Numerics;
using System.Text;
using org.whispersystems.curve25519.csharp;
using Newtonsoft.Json;
using System.Security.Cryptography;
using PublicKey = System.String;
using PrivateKey = System.String;
using Seed = System.String;
using Address = System.String;

namespace csharp_lib_crypto
{
    public partial class WavesCrypto
    {
        public PublicKey PublicKey(Seed seed)
        {
            PrivateKey privateKey = PrivateKey(seed);
            var privateKeyBytes = Base58Decode(privateKey);
            var publicKey = new byte[privateKeyBytes.Length];
            Curve_sigs.curve25519_keygen(publicKey, privateKeyBytes);
            return Base58Encode(publicKey);
        }

        public PrivateKey PrivateKey(Seed seed, int nonce = 0)
        {
            var seedBytes = Encoding.UTF8.GetBytes(seed);
            var stream = new MemoryStream(seedBytes.Length + 4);
            var writer = new BinaryWriter(stream);
            writer.Write(nonce);
            writer.Write(seedBytes);
            var accountSeed = SecureHash(stream.ToArray());
            var hashedSeed = SHA256.ComputeHash(accountSeed.ToArray(), 0, accountSeed.Count());
            var privateKey = hashedSeed.ToArray();
            privateKey[0] &= 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;

            return Base58Encode(privateKey);
        }

        public PrivateKey PrivateKey(Seed seed)
        {
            return PrivateKey(seed, 0);
        }

        public byte[] SecureHash(byte[] message)
        {
            var blake2B = Blake2b(message);
            return Keccak(blake2B.ToArray());
        }

        public Address AddressFromPublicKey(PublicKey publicKey, WavesChainId? chainId)
        {
            var stream = new MemoryStream(26);
            var hash = SecureHash(Base58Decode(publicKey).ToArray());
            var writer = new BinaryWriter(stream);
            writer.Write((byte)1);
            writer.Write((byte)chainId);
            writer.Write(hash.ToArray(), 0, 20);
            var checksum = SecureHash(stream.ToArray());
            writer.Write(checksum.ToArray(), 0, 4);
            return Base58Encode(stream.ToArray());
        }

        public Address Address(Seed seed, WavesChainId? chainId)
        {
            PublicKey publicKey = PublicKey(seed);
            return AddressFromPublicKey(publicKey, chainId);
        }

        public Seed RandomSeed()
        {
            string RunningPath = AppDomain.CurrentDomain.BaseDirectory;
            var bytes = new byte[160 + 5];
            var generator = RandomNumberGenerator.Create();
            generator.GetBytes(bytes);
            var rhash = SHA256.ComputeHash(bytes, 0, 160);
            Array.Copy(rhash, 0, bytes, 160, 5);
            var rand = new BigInteger(bytes);

            if (_seedWords == null)
            {
                var json = File.ReadAllText("SeedWords.txt");
                var items = JsonConvert.DeserializeObject<Dictionary<string, List<string>>>(json);                
                _seedWords = items["words"];                
            }
            var result = new List<BigInteger>();
            for (int i = 0; i < 15; i++)
            {
                result.Add(rand);
                rand = rand >> 11;
            }
            var mask = new BigInteger(new byte[] { 255, 7, 0, 0 }); // 11 lower bits
            return string.Join(" ", result.Select(bigint => _seedWords[(int)(bigint & mask)]));
        }        
    }

    public class KeyPair : IKeyPair
    {
        public PublicKey PublicKey { get; }
        public PrivateKey PrivateKey { get; }

        public KeyPair(PublicKey publicKey, PrivateKey privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        public KeyPair(string seed)
        {
            var crypto = new WavesCrypto();
            PublicKey = crypto.PublicKey(seed);
            PrivateKey = crypto.PrivateKey(seed);
        }
    }
}
