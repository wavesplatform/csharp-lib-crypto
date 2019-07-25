using System.Linq;
using org.whispersystems.curve25519;
using PrivateKey = System.String;
using Seed = System.String;

namespace csharp_lib_crypto
{
    public partial class WavesCrypto
    {
        public byte[] SignBytesWithPrivateKey(byte[] bytes, PrivateKey privateKey)
        {
            return Curve25519.getInstance(Curve25519.BEST).calculateSignature(Base58Decode(privateKey), bytes);
        }
        public byte[] SignBytes(byte[] bytes, Seed seed)
        {
            PrivateKey privateKey = PrivateKey(seed);
            return SignBytesWithPrivateKey(bytes, privateKey);
        }
    }
}
