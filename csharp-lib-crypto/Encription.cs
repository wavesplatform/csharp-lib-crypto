using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace csharp_lib_crypto
{
    public partial class WavesCrypto
    {
        private Aes aes = null;
        private ECDiffieHellmanCng diffieHellman = null;

        public Aes DeriveKeyAndIv(byte[] privateKeyFrom, byte[] publicKeyTo, string prefix)
        {

            byte[] x = { 69, 67, 83, 49, 64, 0, 0, 0 };

            //Prefix above generated array to existing public key array
            privateKeyFrom = x.Concat(privateKeyFrom).ToArray();
            var privateKey = new ECDiffieHellmanCng(CngKey.Import(privateKeyFrom, new CngKeyBlobFormat("ECCPRIVATEBLOB")));
            privateKey.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            privateKey.HashAlgorithm = CngAlgorithm.Sha256;
            privateKey.SecretAppend = StringToBytes(prefix);
            byte[] keyAndIv = privateKey.DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyTo, new CngKeyBlobFormat("PUBLICBLOB")));
            byte[] key = new byte[16];
            Array.Copy(keyAndIv, 0, key, 0, 16);
            byte[] iv = new byte[16];
            Array.Copy(keyAndIv, 16, iv, 0, 16);

            aes = new AesManaged();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            return aes;
        }

        public string MessageDecrypt(byte[] sharedKey, byte[] encryptedMessage, string prefix = "")
        {
            string decryptedMessage;
            this.aes = new AesCryptoServiceProvider();
            aes.Key = sharedKey;
            byte[] iv = new byte[16];
            Array.Copy(sharedKey, 16, iv, 0, 16);
            aes.IV = iv;

            using (var plainText = new MemoryStream())
            {
                using (var decryptor = this.aes.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(plainText, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length);
                    }
                }

                decryptedMessage = Encoding.ASCII.GetString(plainText.ToArray());
            }

            return decryptedMessage;
        }

        public byte[] MessageEncrypt(byte[] sharedKey, string message, string prefix = "")
        {
            byte[] encryptedMessage;

            this.aes = new AesCryptoServiceProvider();
            aes.Key = sharedKey;

            using (var cipherText = new MemoryStream())
            {
                using (var encryptor = this.aes.CreateEncryptor())
                {
                    using (var cryptoStream = new CryptoStream(cipherText, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] ciphertextMessage = Encoding.ASCII.GetBytes(message);
                        cryptoStream.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                    }
                }

                encryptedMessage = cipherText.ToArray();
            }

            return encryptedMessage;
        }

        void Car25519(long[] o)
        {
            int c = 1;
            for (var i = 0; i < 16; i++)
            {
                long v = o[i] + c + 65535;
                c = (int)(Math.Floor(v / 65536.0));
                o[i] = v - c * 65536;
            }
            o[0] += c - 1 + 37 * (c - 1);
        }

        void Sel25519(long[] p, long[] q, long b)
        {
            long t;
            long c = ~(b - 1);
            for (var i = 0; i < 16; i++)
            {
                t = c & (p[i] ^ q[i]);
                p[i] = p[i] ^ t;
                q[i] = q[i] ^ t;
            }
        }

        void Pack25519(byte[] o, long[] n)
        {
            long b;
            var m = new long[16];
            var t = new long[16];
            for (var i = 0; i < 16; i++)
            {
                t[i] = n[i];
            }

            Car25519(t);
            Car25519(t);
            Car25519(t);
            for (var c = 0; c < 2; c++)
            {
                m[0] = t[0] - 0xffed;
                for (var i = 1; i < 15; i++)
                {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] = m[i - 1] & 0xffff;
                }

                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                b = (m[15] >> 16) & 1;
                m[14] = m[14] & 0xffff;
                Sel25519(t, m, (int)(1 - b));
            }

            for (var i = 0; i < 16; i++)
            {
                o[2 * i] = (byte)(t[i] & 0xff);
                o[2 * i + 1] = (byte)(t[i] >> 8);
            }
        }

        void Unpack25519(long[] o, byte[] n)
        {
            for (var i = 0; i < 16; i++)
            {
                o[i] = n[2 * i] + (n[2 * i + 1] << 8);
            }
            o[15] = o[15] & 0x7fff;
        }

        void A(long[] o, long[] a, long[] b)
        {
            for (var i = 0; i < 16; i++)
            {
                o[i] = a[i] + b[i];
            }
        }

        public void Z(long[] o, long[] a, long[] b)
        {
            for (var i = 0; i < 16; i++)
            {
                o[i] = a[i] - b[i];
            }
        }

        void M(long[] o, long[] a, long[] b)
        {
            var at = new long[32];
            var ab = new long[16];
            for (var i = 0; i < 16; i++)
            {
                ab[i] = b[i];
            }

            long v;
            for (var i = 0; i < 16; i++)
            {
                v = a[i];
                for (var j = 0; j < 16; j++)
                {
                    at[j + i] += v * ab[j];
                }
            }

            for (var i = 0; i < 15; i++)
            {
                at[i] += 38 * at[i + 16];
            }
            // t15 left as is

            // first car
            long c = 1;
            for (var i = 0; i < 16; i++)
            {
                v = at[i] + c + 65535;
                c = (long)Math.Floor(v / 65536.0);
                at[i] = v - c * 65536;
            }

            at[0] += c - 1 + 37 * (c - 1);

            // second car
            c = 1;
            for (var i = 0; i < 16; i++)
            {
                v = at[i] + c + 65535;
                c = (long)Math.Floor(v / 65536.0);
                at[i] = v - c * 65536;
            }

            at[0] += c - 1 + 37 * (c - 1);

            for (var i = 0; i < 16; i++)
            {
                o[i] = at[i];
            }
        }

        void S(long[] o, long[] a)
        {
            M(o, a, a);
        }

        void Inv25519(long[] o, long[] i)
        {
            var c = new long[16];
            for (var a = 0; a < 16; a++)
            {
                c[a] = i[a];
            }

            for (var a = 253; a >= 0; a--)
            {
                S(c, c);
                if (a != 2 && a != 4)
                {
                    M(c, c, i);
                }
            }

            for (var a = 0; a < 16; a++)
            {
                o[a] = c[a];
            }
        }

        void CryptoScalarMult(byte[] q, byte[] n, byte[] p)
        {
            var z = new byte[32];
            var x = new long[80];

            var a = new long[16];
            var b = new long[16];
            var c = new long[16];
            var d = new long[16];
            var e = new long[16];
            var f = new long[16];

            for (var i = 0; i < 31; i++)
            {
                z[i] = n[i];
            }

            z[31] = (byte)(((n[31] & 127)) | 64);
            z[0] = (byte)(z[0] & 248);
            Unpack25519(x, p);

            for (var i = 0; i < 16; i++)
            {
                b[i] = x[i];
                d[i] = 0;
                a[i] = 0;
                c[i] = 0;
            }

            a[0] = 1;
            d[0] = 1;
            for (int i = 254; i >= 0; i--)
            {
                int r = ((z[i >> 3]) >> (i & 7)) & 1;
                Sel25519(a, b, r);
                Sel25519(c, d, r);
                A(e, a, c);
                Z(a, a, c);
                A(c, b, d);
                Z(b, b, d);
                S(d, e);
                S(f, a);
                M(a, c, a);
                M(c, b, e);
                A(e, a, c);
                Z(a, a, c);
                S(b, a);
                Z(c, d, f);

                var _121665 = new long[16];
                _121665[0] = 0xdb41;
                _121665[1] = 1;

                M(a, c, _121665);
                A(a, a, d);
                M(c, c, a);
                M(a, d, f);
                M(d, b, x);
                S(b, e);
                Sel25519(a, b, r);
                Sel25519(c, d, r);
            }

            for (var i = 0; i < 16; i++)
            {
                x[i + 16] = a[i];
                x[i + 32] = c[i];
                x[i + 48] = b[i];
                x[i + 64] = d[i];
            }

            var x32 = new long[80 - 32];
            Array.Copy(x, 32, x32, 0, 80 - 32);
            var x16 = new long[80 - 16];
            Array.Copy(x, 16, x16, 0, 80 - 16);

            Inv25519(x32, x32);
            M(x16, x16, x32);
            Pack25519(q, x16);
        }

        public byte[] SharedKey(byte[] secretKey, byte[] publicKey)
        {
            var sharedKey = new byte[32];
            CryptoScalarMult(sharedKey, secretKey, publicKey);
            return sharedKey;
        }

        public byte[] SharedKey(byte[] secretKey, byte[] publicKey, string prefix)
        {
            var sharedKey = new byte[32];
            CryptoScalarMult(sharedKey, secretKey, publicKey);
            var prefixHash = SHA256.ComputeHash(StringToBytes(prefix));
            return new HMACSHA256(sharedKey).ComputeHash(prefixHash);
        }
    }
}
