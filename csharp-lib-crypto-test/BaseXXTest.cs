using Microsoft.VisualStudio.TestTools.UnitTesting;
using csharp_lib_crypto;

namespace csharp_lib_crypto_test
{
    [TestClass]
    public class BaseXXTest
    {

        [TestMethod]
        public void Base58EncodeDecodeTest()
        {
            var address = "3N1JMgUfzYUZinPrzPWeRa6yqN67oo57XR7";
            var crypto = new WavesCrypto();

            Assert.AreEqual(address, crypto.Base58Encode(crypto.Base58Decode(address)));
        }

        [TestMethod]
        public void Base16EncodeDecodeTest()
        {
            var hex = "b8cdf75a74091da77a952eee061edc7a6caa54e3b6bfdb7412f90fc7d62dd690";
            var crypto = new WavesCrypto();

            Assert.AreEqual(hex, crypto.Base16Encode(crypto.Base16Decode(hex)));
        }

        [TestMethod]
        public void Base64EncodeDecodeTest()
        {
            var base64 = "0LHRg9C70YzQtNC+0LfQtdGA0L/QtdGA0LXQtdC30LbQsNC10YLQvNC+0Y7Qs9C+0LvQvtCy0YM=";
            var crypto = new WavesCrypto();

            Assert.AreEqual(base64, crypto.Base64Encode(crypto.Base64Decode(base64)));
        }
    }
}
