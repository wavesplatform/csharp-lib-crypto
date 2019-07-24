using Microsoft.VisualStudio.TestTools.UnitTesting;
using csharp_lib_crypto;

namespace csharp_lib_crypto_test
{
    [TestClass]
    public class SignTest
    {
        [TestMethod]
        public void TestPublicAndPrivateKey()
        {
            var crypto = new WavesCrypto();
            var seed = "seed seed seed seed seed seed";
            var publicKeyInit = "22e8aRY89tDZhcaVmPvxxorj7e5mtbiUtG6MYN5agt8z";
            var privateKeyInit = "8bg5KM2n5kKQE6bVZssvwMEivc6ctyKahfGLkQfszZfY";

            var bytes = new byte[] { 1, 2, 3, 4};

            var sign = crypto.SignBytes(bytes, seed);
            var sign2 = crypto.SignBytesWithPrivateKey(bytes, privateKeyInit);
            Assert.IsTrue(crypto.VerifySignature(publicKeyInit, bytes, sign));
            Assert.IsTrue(crypto.VerifySignature(publicKeyInit, bytes, sign2));
        }
    }
}
