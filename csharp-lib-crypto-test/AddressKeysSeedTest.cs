using Microsoft.VisualStudio.TestTools.UnitTesting;
using csharp_lib_crypto;

namespace csharp_lib_crypto_test
{
    [TestClass]
    public class AddressKeysSeedTest
    {
        [TestMethod]
        public void TestPublicAndPrivateKey()
        {       
            var crypto = new WavesCrypto();
            var seed = "seed seed seed seed seed seed";
            var publicKeyInit = "22e8aRY89tDZhcaVmPvxxorj7e5mtbiUtG6MYN5agt8z";
            var privateKeyInit = "8bg5KM2n5kKQE6bVZssvwMEivc6ctyKahfGLkQfszZfY";
            var addressInit = "3P6zgpT1vmqfPRwQkx2HTULBheD8T3RRkKg";

            var address = crypto.Address(seed, WavesChainId.MAIN_NET_CHAIN_ID);
            var publicKey = crypto.PublicKey(seed);
            var privateKey = crypto.PrivateKey(seed);
            Assert.AreEqual(privateKey, privateKeyInit);
            Assert.AreEqual(publicKey, publicKeyInit);
            Assert.AreEqual(address, addressInit);
            Assert.IsTrue(crypto.VerifyAddress(address, WavesChainId.MAIN_NET_CHAIN_ID, publicKey));
            Assert.IsTrue(crypto.VerifyPublicKey(publicKeyInit));
        }

        [TestMethod]
        public void TestSeedGeneration()
        {
            var crypto = new WavesCrypto();
            string seed = crypto.RandomSeed();
            Assert.AreEqual(15, seed.Split(' ').Length);
        }
    }
}
