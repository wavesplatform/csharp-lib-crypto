using Microsoft.VisualStudio.TestTools.UnitTesting;
using csharp_lib_crypto;

namespace csharp_lib_crypto_test
{
    [TestClass]
    public class UtilsTest
    {
        [TestMethod]
        public void TestBytes()
        {
            var crypto = new WavesCrypto();
            var size = 5;
            var bytes = crypto.RandomBytes(size);

            Assert.AreEqual(bytes.Length, size);

            var bytes2 = new byte[] { 6, 7, 8, 4 };
            var stringFromBytes = crypto.BytesToString(bytes2);
            var bytesFromString = crypto.StringToBytes(stringFromBytes);
            CollectionAssert.AreEqual(bytesFromString, bytes2);
        }
    }
}
