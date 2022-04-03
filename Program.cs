using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace DoubleRatchet
{
    public class Program
    {
        public static RatchetMessage? MessageFromAlice;
        public static RatchetMessage? MessageFromBob;
        public static AsymmetricCipherKeyPair aliceSignedIdentityKey =
            DoubleRatchetProtocol.GenerateDHKeyPair();
        public static AsymmetricCipherKeyPair bobSignedIdentityKey =
            DoubleRatchetProtocol.GenerateDHKeyPair();
        public static AsymmetricCipherKeyPair bobSignedPreKey =
            DoubleRatchetProtocol.GenerateDHKeyPair();

        public static void Main(string[] args)
        {
            var aliceDR = new DoubleRatchetProtocol(
                "sample",
                aliceSignedIdentityKey,
                ((ECPublicKeyParameters)(bobSignedIdentityKey.Public)).Q.GetEncoded(),
                ((ECPublicKeyParameters)(bobSignedPreKey.Public)).Q.GetEncoded());
            DoubleRatchetProtocol? bobDR = null;
            while (true)
            {
                if (MessageFromAlice != null)
                {
                    DisplayAliceMessage(MessageFromAlice, ref bobDR);
                    MessageFromAlice = null;
                }

                if (MessageFromBob != null)
                {
                    DisplayBobMessage(MessageFromBob, aliceDR);
                    MessageFromBob = null;
                }

                Console.Write("Select your action: Send as Alice (A) | Send as Bob (B) | Quit (Q)");
                var action = Console.ReadLine();
                switch (action)
                {
                    case "A":
                        MessageFromAlice = HandleAliceInput(aliceDR);
                        break;
                    case "B":
                        MessageFromBob = HandleBobInput(bobDR!);
                        break;
                    case "Q":
                        return;
                    default:
                        break;
                }
            }

        }

        public static RatchetMessage HandleAliceInput(
            DoubleRatchetProtocol aliceDR)
        {
            Console.Write("(Alice): ");

            string? aliceMessage = null;
            while (aliceMessage == null) aliceMessage = Console.ReadLine();

            return aliceDR.RatchetEncrypt(Encoding.UTF8.GetBytes(aliceMessage));
        }

        public static RatchetMessage HandleBobInput(
            DoubleRatchetProtocol bobDR)
        {
            Console.Write("(Bob): ");

            string? bobMessage = null;
            while (bobMessage == null) bobMessage = Console.ReadLine();

            return bobDR.RatchetEncrypt(Encoding.UTF8.GetBytes(bobMessage));
        }

        public static void DisplayAliceMessage(
            RatchetMessage aliceMessage,
            ref DoubleRatchetProtocol? bobDR)
        {
            Console.WriteLine(
                "(received from Alice): " +
                System.Text.Json.JsonSerializer.Serialize(aliceMessage));

            if (bobDR == null)
            {
                bobDR = new DoubleRatchetProtocol(
                    "sample",
                    bobSignedIdentityKey,
                    bobSignedPreKey,
                    ((ECPublicKeyParameters)(aliceSignedIdentityKey.Public))
                        .Q.GetEncoded(),
                    aliceMessage.ephemeralPublicKey!);
            }

            var plaintext = bobDR.RatchetDecrypt(aliceMessage);
            Console.WriteLine(
                "(decrypted): " + Encoding.UTF8.GetString(plaintext));
        }

        public static void DisplayBobMessage(
            RatchetMessage bobMessage,
            DoubleRatchetProtocol aliceDR)
        {
            Console.WriteLine(
                "(received from Bob): " +
                System.Text.Json.JsonSerializer.Serialize(bobMessage));
            var plaintext = aliceDR.RatchetDecrypt(bobMessage);
            Console.WriteLine(
                "(decrypted): " + Encoding.UTF8.GetString(plaintext));
        }
    }
}