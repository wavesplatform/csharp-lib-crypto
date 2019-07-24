using Microsoft.VisualStudio.TestTools.UnitTesting;
using csharp_lib_crypto;

namespace csharp_lib_crypto_test
{
    [TestClass]
    public class MessagingTest
    {
        [TestMethod]
        public void TestSharedKey()
        {
            var crypto = new WavesCrypto();
            var publicKeyInit = "22e8aRY89tDZhcaVmPvxxorj7e5mtbiUtG6MYN5agt8z";
            var privateKeyInit = "8tg5KM2n5kKQE6bVZssvwMEivc6ctyKahfGLkQfszZfY";

            var sharedKey =  crypto.SharedKey(crypto.Base58Decode(privateKeyInit), crypto.Base58Decode(publicKeyInit), "");
            var message = "hellololo";
            var messageEncript = crypto.MessageEncrypt(sharedKey, message,"");
            var messageDecrypt = crypto.MessageDecrypt(sharedKey, messageEncript, "");
            
            Assert.AreEqual(messageDecrypt, message);
        }
    }
}
