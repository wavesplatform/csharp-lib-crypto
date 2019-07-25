using System.Linq;
using Blake2Sharp;

namespace csharp_lib_crypto
{
    public partial class WavesCrypto
    {
        public byte[] Blake2b(byte[] input)
        {
            var blakeConfig = new Blake2BConfig { OutputSizeInBits = 256 };
            return Blake2B.ComputeHash(input, 0, input.Count(), blakeConfig);
        }

        public byte[] Keccak(byte[] input)
        {
            Keccak256.Initialize();
            Keccak256.TransformBytes(input.ToArray(), 0, input.Count());
            return Keccak256.TransformFinal().GetBytes();
        }

        public byte[] Sha256(byte[] input)
        {
            return SHA256.ComputeHash(input.ToArray(), 0, input.Count());
        }
    }
}
