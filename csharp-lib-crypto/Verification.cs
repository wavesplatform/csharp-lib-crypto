using System.Linq;
using PublicKey = System.String;
using Address = System.String;
using org.whispersystems.curve25519;

namespace csharp_lib_crypto
{
    public partial class WavesCrypto
    {
        public bool VerifySignature(PublicKey publicKey, byte[] bytes, byte[] signature)
        {
            return Curve25519.getInstance(Curve25519.BEST).verifySignature(Base58Decode(publicKey).ToArray(), bytes.ToArray(), signature.ToArray());
        }
        public bool VerifyPublicKey(PublicKey publicKey)
        {
            return Base58Decode(publicKey).Count() == WavesCryptoConstants.PUBLIC_KEY_LENGTH;
        }

        public bool VerifyAddress(Address address, WavesChainId? chainId, PublicKey publicKey)
        {
            return AddressFromPublicKey(publicKey, chainId) == address;
        }
    }
}
