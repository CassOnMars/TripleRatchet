using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace TripleRatchet
{
    public class Program
    {
        public static RatchetMessage? MessageFromAlice;
        public static RatchetMessage? MessageFromRoom;
        public static AsymmetricCipherKeyPair aliceSignedIdentityKey =
            DoubleRatchetProtocol.GenerateDHKeyPair();
        public static void Main(string[] args)
        {
            var vssSIK = new Dictionary<int, VerifiableSecretShare>();
            var vssSPK = new Dictionary<int, VerifiableSecretShare>();
            var vssSIKScalars = new Dictionary<int, BigInteger>();
            var vssSPKScalars = new Dictionary<int, BigInteger>();
            for (var i = 1; i <= 5; i++)
            {
                vssSIKScalars[i] = ((ECPrivateKeyParameters)
                        (DoubleRatchetProtocol.GenerateDHKeyPair().Private)).D;
                vssSPKScalars[i] = ((ECPrivateKeyParameters)
                        (DoubleRatchetProtocol.GenerateDHKeyPair().Private)).D;
                vssSIK[i] = new VerifiableSecretShare(
                    NistNamedCurves.GetByName("P-256"),
                    NistNamedCurves.GetByName("P-256").G,
                    vssSIKScalars[i],
                    3,
                    5,
                    i
                );
                vssSPK[i] = new VerifiableSecretShare(
                    NistNamedCurves.GetByName("P-256"),
                    NistNamedCurves.GetByName("P-256").G,
                    vssSPKScalars[i],
                    3,
                    5,
                    i
                );
            }

            var reads = new Dictionary<int, Dictionary<int, byte[]>>();
            var writes = new Dictionary<int, Dictionary<int, byte[]>>();

            for (var i = 1; i <= 5; i++)
            {
                reads[i] = new Dictionary<int, byte[]>();
            }

            while (vssSIK[5].State != VerifiableSecretShare.Round.Ready)
            {
                for (var i = 1; i <= 5; i++)
                {
                    writes[i] = vssSIK[i].Next(reads[i]);
                }

                for (var i = 1; i <= 5; i++)
                {
                    for (var j = 1; j <= 5; j++)
                    {
                        if (i != j && writes[j].Count > 0)
                        {
                            reads[i][j] = writes[j][i];
                        }
                    }
                }
            }

            
            for (var i = 1; i <= 5; i++)
            {
                reads[i] = new Dictionary<int, byte[]>();
            }

            while (vssSPK[5].State != VerifiableSecretShare.Round.Ready)
            {
                for (var i = 1; i <= 5; i++)
                {
                    writes[i] = vssSPK[i].Next(reads[i]);
                }

                for (var i = 1; i <= 5; i++)
                {
                    for (var j = 1; j <= 5; j++)
                    {
                        if (i != j && writes[j].Count > 0)
                        {
                            reads[i][j] = writes[j][i];
                        }
                    }
                }
            }

            var aliceDR = new DoubleRatchetProtocol(
                "sample",
                aliceSignedIdentityKey,
                vssSIK[1].PublicKey!.GetEncoded(),
                vssSPK[1].PublicKey!.GetEncoded());
            DoubleRatchetProtocol? roomDR = null;
            while (true)
            {
                if (MessageFromAlice != null)
                {
                    DisplayAliceMessage(
                        MessageFromAlice,
                        vssSIK,
                        vssSPK,
                        ref roomDR);
                    MessageFromAlice = null;
                }

                if (MessageFromRoom != null)
                {
                    DisplayRoomMessage(MessageFromRoom, aliceDR);
                    MessageFromRoom = null;
                }

                Console.Write("Select your action: Send as Alice (A) | Send as Room (R) | Quit (Q)");
                var action = Console.ReadLine();
                switch (action)
                {
                    case "A":
                        MessageFromAlice = HandleAliceInput(aliceDR);
                        break;
                    case "R":
                        MessageFromRoom = HandleRoomInput(roomDR!);
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

        public static RatchetMessage HandleRoomInput(
            DoubleRatchetProtocol roomDR)
        {
            Console.Write("(Room): ");

            string? roomMessage = null;
            while (roomMessage == null) roomMessage = Console.ReadLine();

            return roomDR.RatchetEncrypt(Encoding.UTF8.GetBytes(roomMessage));
        }

        public static void DisplayAliceMessage(
            RatchetMessage aliceMessage,
            Dictionary<int, VerifiableSecretShare> roomSignedIdentityKey,
            Dictionary<int, VerifiableSecretShare> roomSignedPreKey,
            ref DoubleRatchetProtocol? roomDR)
        {
            Console.WriteLine(
                "(received from Alice): " +
                System.Text.Json.JsonSerializer.Serialize(aliceMessage));

            if (roomDR == null)
            {
                roomDR = new DoubleRatchetProtocol(
                    "sample",
                    roomSignedIdentityKey,
                    roomSignedPreKey,
                    ((ECPublicKeyParameters)(aliceSignedIdentityKey.Public))
                        .Q.GetEncoded(),
                    aliceMessage.ephemeralPublicKey!);
            }

            var plaintext = roomDR.RatchetDecrypt(aliceMessage);
            Console.WriteLine(
                "(decrypted): " + Encoding.UTF8.GetString(plaintext));
        }

        public static void DisplayRoomMessage(
            RatchetMessage roomMessage,
            DoubleRatchetProtocol aliceDR)
        {
            Console.WriteLine(
                "(received from Room): " +
                System.Text.Json.JsonSerializer.Serialize(roomMessage));
            var plaintext = aliceDR.RatchetDecrypt(roomMessage);
            Console.WriteLine(
                "(decrypted): " + Encoding.UTF8.GetString(plaintext));
        }
    }
}
