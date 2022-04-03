using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DoubleRatchet
{
    public class DoubleRatchetProtocol
    {
        public static X9ECParameters curve = NistNamedCurves.GetByName("P-256");

        public static ECDomainParameters ecParam =
            new ECDomainParameters(
                curve.Curve,
                curve.G,
                curve.N,
                curve.H,
                curve.GetSeed());


        public AsymmetricCipherKeyPair SendingEphemeralKey { get; set; }

        public ECPublicKeyParameters? ReceivingEphemeralPublicKey { get; set; }

        private static SecureRandom random = new SecureRandom();

        private byte[] rootKey;

        private byte[] sendingChainKey;

        private byte[]? receivingChainKey;

        private int sentN;

        private int receivedN;

        private List<byte[]> receivingMessageKeys = new List<byte[]>();

        private string applicationName;

        // DH1 = DH(SIK_A, SPK_B)
        // DH2 = DH(EK_A, SIK_B)
        // DH3 = DH(EK_A, SPK_B)
        // RK = KDF(DH1 || DH2 || DH3)
        public DoubleRatchetProtocol(
            string applicationName,
            AsymmetricCipherKeyPair aliceSignedIdentityKey,
            byte[] bobSignedIdentityKey,
            byte[] bobSignedPreKey)
        {
            this.applicationName = applicationName;
            var aliceEphemeralKey = GenerateDHKeyPair();
            var dh1 = this.CalculateDHKeyAgreement(
                aliceSignedIdentityKey,
                bobSignedPreKey);
            var dh2 = this.CalculateDHKeyAgreement(
                aliceEphemeralKey,
                bobSignedIdentityKey);
            var dh3 = this.CalculateDHKeyAgreement(
                aliceEphemeralKey,
                bobSignedPreKey);
            
            var payload = DeriveRootKey(
                new byte[0],
                dh1.Concat(dh2).Concat(dh3).ToArray(),
                64);
            this.rootKey = payload.Take(32).ToArray();
            this.sendingChainKey = payload.Skip(32).ToArray();
            this.SendingEphemeralKey = aliceEphemeralKey;
        }

        public DoubleRatchetProtocol(
            string applicationName,
            AsymmetricCipherKeyPair bobSignedIdentityKey,
            AsymmetricCipherKeyPair bobSignedPreKey,
            byte[] aliceSignedIdentityKey,
            byte[] aliceEphemeralKey)
        {
            this.applicationName = applicationName;
            var dh1 = this.CalculateDHKeyAgreement(
                bobSignedPreKey,
                aliceSignedIdentityKey);
            var dh2 = this.CalculateDHKeyAgreement(
                bobSignedIdentityKey,
                aliceEphemeralKey);
            var dh3 = this.CalculateDHKeyAgreement(
                bobSignedPreKey,
                aliceEphemeralKey);
            var payload = DeriveRootKey(
                new byte[0],
                dh1.Concat(dh2).Concat(dh3).ToArray(),
                64);
            this.rootKey = payload.Take(32).ToArray();
            this.receivingChainKey = payload.Skip(32).ToArray();

            var alicePoint = ecParam.Curve.DecodePoint(aliceEphemeralKey);
            var aliceEphemeralPubKey =
                new ECPublicKeyParameters(alicePoint, ecParam);
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(aliceEphemeralPubKey.Q.GetEncoded()));
            this.ReceivingEphemeralPublicKey = aliceEphemeralPubKey;
            
        }

        public RatchetMessage RatchetEncrypt(byte[] plaintext)
        {
            if (this.receivedN > 0 )
            {
                Console.WriteLine("Ratcheting Send");

                var ephemeralKey = GenerateDHKeyPair();
                this.SendingEphemeralKey = ephemeralKey;
                this.sentN = 0;
                var payload = DeriveRootKey(
                    this.rootKey,
                    this.CalculateDHKeyAgreement(
                        ephemeralKey,
                        this.ReceivingEphemeralPublicKey!.Q.GetEncoded()),
                    64);
                this.rootKey = payload.Take(32).ToArray();
                this.sendingChainKey = payload.Skip(32).ToArray();
            }

            var messageEncryptionKey = this.DeriveChainKey(
                ChainKey.MessageKey,
                this.sendingChainKey);
            var aeadValue = this.DeriveChainKey(
                ChainKey.AEADValue,
                messageEncryptionKey);
            this.sendingChainKey = this.DeriveChainKey(
                ChainKey.ChainKey,
                this.sendingChainKey);
            var ciphertext = this.EncryptAESGCM(
                messageEncryptionKey,
                plaintext,
                aeadValue);
            byte[]? ephemeralPublicKey = null;

            if (this.sentN == 0)
            {
                ephemeralPublicKey = ((ECPublicKeyParameters)
                    (this.SendingEphemeralKey.Public)).Q.GetEncoded();
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(ephemeralPublicKey));
            }

            this.sentN++;

            return new RatchetMessage(ephemeralPublicKey, ciphertext);
        }

        public byte[] RatchetDecrypt(RatchetMessage message)
        {  
            if (message.ephemeralPublicKey != null)
            {
                var point = ecParam.Curve.DecodePoint(
                    message.ephemeralPublicKey);
                if (!this.ReceivingEphemeralPublicKey?.Q.Equals(point) ?? true)
                {
                    Console.WriteLine("Ratcheting Receive");
                    this.ReceivingEphemeralPublicKey =
                        new ECPublicKeyParameters(point, ecParam);
                    var payload = DeriveRootKey(
                        this.rootKey,
                        this.CalculateDHKeyAgreement(
                            this.SendingEphemeralKey,
                            message.ephemeralPublicKey),
                        64);
                    this.rootKey = payload.Take(32).ToArray();
                    this.receivingChainKey = payload.Skip(32).ToArray();
                    this.receivedN = 0;
                    this.receivingMessageKeys = new List<byte[]>();
                }
            }

            var messageDecryptionKey = this.DeriveChainKey(
                ChainKey.MessageKey,
                this.receivingChainKey!);
            this.receivingChainKey = this.DeriveChainKey(
                ChainKey.ChainKey,
                this.receivingChainKey!);
            this.receivingMessageKeys.Add(messageDecryptionKey);

            try
            {
                var plaintext = this.DecryptAESGCM(messageDecryptionKey, message.ciphertext);
                this.receivingMessageKeys.Remove(messageDecryptionKey);
                this.receivedN++;
                return plaintext;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return this.RatchetDecrypt(message);
            }
        }

        public static AsymmetricCipherKeyPair GenerateDHKeyPair()
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(ecParam, random));
            return generator.GenerateKeyPair();
        }

        internal byte[] CalculateDHKeyAgreement(
            AsymmetricCipherKeyPair privateKey,
            byte[] publicKey)
        {
            var point = ecParam.Curve.DecodePoint(publicKey);
            var ecPubKey = new ECPublicKeyParameters(point, ecParam);

            var agreement = new ECDHBasicAgreement();
            agreement.Init(privateKey.Private);
            var secret = agreement.CalculateAgreement(ecPubKey);

            return secret.ToByteArrayUnsigned();
        }

        internal byte[] DeriveRootKey(byte[] salt, byte[] input, int length)
        {
            var hkdf = new HkdfBytesGenerator(new Sha3Digest());
            hkdf.Init(new HkdfParameters(
                input,
                salt,
                Encoding.UTF8.GetBytes(this.applicationName)));
            var outputBytes = new byte[length];
            hkdf.GenerateBytes(outputBytes, 0, length);
            return outputBytes;
        }

        internal byte[] DeriveChainKey(ChainKey keyType, byte[] chainKey)
        {
            var hmac = new HMac(new Sha3Digest());
            hmac.Init(new KeyParameter(chainKey));
            hmac.Update((byte)keyType);
            var outputBytes = new byte[32];
            hmac.DoFinal(outputBytes, 0);

            return outputBytes;
        }

        internal AESCiphertext EncryptAESGCM(
            byte[] inputKey,
            byte[] message,
            byte[] associatedData)
        {
            var iv = new byte[12];
            random.NextBytes(iv);
            var cipher = new GcmBlockCipher(new AesEngine());
            var param = new AeadParameters(
                new KeyParameter(inputKey),
                128,
                iv,
                associatedData);
            cipher.Init(true, param);

            var outputBytes = new byte[cipher.GetOutputSize(message.Length)];
            var length = cipher.ProcessBytes(
                message,
                0,
                message.Length,
                outputBytes,
                0);
            cipher.DoFinal(outputBytes, length);
            
            return new AESCiphertext(iv, outputBytes, associatedData);
        }

        internal byte[] DecryptAESGCM(
            byte[] inputKey,
            AESCiphertext ciphertext)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var param = new AeadParameters(
                new KeyParameter(inputKey),
                128,
                ciphertext.IV,
                ciphertext.AssociatedData);
            cipher.Init(false, param);

            var outputBytes =
                new byte[cipher.GetOutputSize(ciphertext.Ciphertext.Length)];
            var length = cipher.ProcessBytes(
                ciphertext.Ciphertext,
                0,
                ciphertext.Ciphertext.Length,
                outputBytes,
                0);
            cipher.DoFinal(outputBytes, length);

            return outputBytes;
        }
    }

    public record RatchetMessage(
        byte[]? ephemeralPublicKey,
        AESCiphertext ciphertext);

    public record AESCiphertext(
        byte[] IV,
        byte[] Ciphertext,
        byte[] AssociatedData);

    public enum ChainKey : byte
    {
        MessageKey = 0x01,
        ChainKey = 0x02,
        AEADValue = 0x03,
    }
}