using Microsoft.VisualStudio.TestTools.UnitTesting;
using csharp_lib_crypto;
using System.Security.Cryptography;


namespace csharp_lib_crypto_test
{
    [TestClass]
    public class MessagingTest
    {
        [TestMethod]
        public void TestSharedKey()
        {
            var crypto = new WavesCrypto();
            var a = new KeyPair("1f98af466da54014bdc08bfbaaaf3c67");
            var b = new KeyPair("1f98af466da54014bdc08bfbaaaf3c671f98af466da54014bdc08bfbaaaf3c67");

            var sharedKey1 =  crypto.SharedKey(crypto.Base58Decode(a.PrivateKey), crypto.Base58Decode(b.PublicKey), "waves");
            var sharedKey2 = crypto.SharedKey(crypto.Base58Decode(b.PrivateKey), crypto.Base58Decode(a.PublicKey), "waves");
            CollectionAssert.AreEqual(sharedKey1, sharedKey2);

            var message = "Waves is awesome!";
            var messageEncript = crypto.MessageEncrypt(sharedKey1, message);
            var messageDecrypt = crypto.MessageDecrypt(sharedKey1, messageEncript);
            
            Assert.AreEqual(messageDecrypt, message);
        }
    }
}
