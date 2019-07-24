using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;

using System.Security.Cryptography;
using HashLib;
using PublicKey = System.String;
using PrivateKey = System.String;

namespace csharp_lib_crypto
{
    public partial class WavesCrypto : IWavesCrypto
    {
        private static readonly SHA256Managed SHA256 = new SHA256Managed();
        private static readonly IHash Keccak256 = HashFactory.Crypto.SHA3.CreateKeccak256();
        private static List<string> _seedWords;

        public class KeyPair : IKeyPair
        {
            public PublicKey PublicKey { get; }
            public PrivateKey PrivateKey { get; }

            public KeyPair(PublicKey publicKey, PrivateKey privateKey)
            {
                PublicKey = publicKey;
                PrivateKey = privateKey;
            }
        }     

        public byte[] RandomBytes(int size)
        {
            byte[] randomBytes = new byte[size];
            RNGCryptoServiceProvider rnd = new RNGCryptoServiceProvider();
            rnd.GetBytes(randomBytes);
            return randomBytes;
        }

        public byte[] StringToBytes(string input)
        {
            return Encoding.ASCII.GetBytes(input);
        }

        public string BytesToString(byte[] input)
        {
            return Encoding.ASCII.GetString(input);
        }

        IKeyPair IWavesCrypto.KeyPair(string seed)
        {
            return new KeyPair(PublicKey(seed), PrivateKey(seed));
        }


        
    }
}
