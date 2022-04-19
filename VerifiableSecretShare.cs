using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace TripleRatchet
{
    public class VerifiableSecretShare
    {
        private X9ECParameters _curve;

        private int _threshold;

        private int _total;

        private ECDomainParameters _param;

        private ECPoint _point;

        private SecureRandom _random;

        private ECKeyPairGenerator _keyPairGenerator;

        private int _id;

        private BigInteger _myScalar;

        private Dictionary<int, byte[]> _fragmentsForCounterparties;

        private ECPoint? _myPoint;

        private BigInteger? _zkPoK;

        private ECPoint? _randomCommitment;

        private Dictionary<int, byte[]>? _counterpartyCommitments;

        public BigInteger SecretScalar { get; init; }

        public ECPoint? PublicKey { get; set; }

        public Round State { get; set; }

        public VerifiableSecretShare(
            X9ECParameters curve,
            ECPoint point,
            BigInteger secretScalar,
            int threshold,
            int total,
            int id
        )
        {
            this._curve = curve;
            this._threshold = threshold;
            this._id = id;
            this._total = total;
            this.SecretScalar = secretScalar;
            this._param = new ECDomainParameters(
                curve.Curve,
                curve.G,
                curve.N,
                curve.H,
                curve.GetSeed()
            );
            this._point = point;

            if (!point.Curve.Equals(this._curve.Curve))
            {
                throw new ArgumentException("Curve mismatched");
            }

            this._random = new SecureRandom();
            this._keyPairGenerator = new ECKeyPairGenerator();
            this._keyPairGenerator.Init(
                new ECKeyGenerationParameters(this._param, this._random)
            );
            
            var coefficients = new List<BigInteger>(threshold);

            coefficients.Add(secretScalar);

            for (var i = 0; i < threshold - 1; i++)
            {
                var pair = this._keyPairGenerator.GenerateKeyPair();
                coefficients.Add(((ECPrivateKeyParameters)(pair.Private)).D);
            }

            this._myScalar = BigInteger.Zero;
            this._fragmentsForCounterparties = new Dictionary<int, byte[]>();

            for (var i = 1; i <= total; i++)
            {
                var fragment = coefficients.Last();

                for (var j = coefficients.Count() - 2; j >= 0; j--)
                {
                    // y = 3x^4 + 7x^3 + 8x^2 + 9x + 234
                    fragment = fragment.Multiply(new BigInteger(i.ToString()))
                                    .Add(coefficients[j]);
                }

                if (i == this._id)
                {
                    this._myScalar = fragment;
                }
                else
                {
                    this._fragmentsForCounterparties[i] =
                        Encoding.UTF8.GetBytes(fragment.ToString());
                }
            }

            this.State = Round.Initialized;
        }

        public Dictionary<int, byte[]> SendFragments()
        {
            return this._fragmentsForCounterparties;
        }

        public Dictionary<int, byte[]> SendProofCommitments(
            Dictionary<int, byte[]> read
        )
        {
            for (var i = 1; i <= this._total; i++)
            {
                if (i != this._id)
                {
                    Console.WriteLine(
                        $"received frags (len={read[i].Length}) from {i} " +
                        $"to {this._id}");
                    var fragment = new BigInteger(
                        Encoding.UTF8.GetString(read[i]));
                    this._myScalar = this._myScalar.Add(fragment);
                }
            }

            // challenge = H(myPoint||randomECPoint)
            this._myPoint = this._point.Multiply(this._myScalar).Normalize();
            var ecCommitment = this._keyPairGenerator.GenerateKeyPair();
            var ecCommitmentScalar = ((ECPrivateKeyParameters)
                (ecCommitment.Private)).D;
            var ecCommitmentPoint = (this._point.Multiply(ecCommitmentScalar));
            var digest = new Sha3Digest();
            var myPointConcatRandomECPoint = this._myPoint.GetEncoded().Concat(
                ecCommitmentPoint.GetEncoded()
            ).ToArray();
            var challenge = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(
                myPointConcatRandomECPoint,
                0,
                myPointConcatRandomECPoint.Length);
            digest.DoFinal(challenge, 0);


            // z = myScalar * challenge + randomECScalar
            var zkPoK = this._myScalar.Multiply(new BigInteger(challenge))
                .Add(ecCommitmentScalar);

            // commitments = H(randomECPoint||z)
            digest = new Sha3Digest();
            var randomECPointConcatZKPoK = 
                ecCommitmentPoint.GetEncoded()
                .Concat(Encoding.UTF8.GetBytes(zkPoK.ToString())).ToArray();
            var commitment = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(
                randomECPointConcatZKPoK,
                0,
                randomECPointConcatZKPoK.Length);
            digest.DoFinal(commitment, 0);

            this._zkPoK = zkPoK;
            this._randomCommitment = ecCommitmentPoint;

            var send = new Dictionary<int, byte[]>();

            for (var i = 1; i <= this._total; i++)
            {
                if (i != this._id)
                {
                    send[i] = commitment;
                }
            }

            return send;
        }

        public Dictionary<int, byte[]> SendPointsWithProof(
            Dictionary<int, byte[]> read
        )
        {
            this._counterpartyCommitments = new Dictionary<int, byte[]>();
            for (int i = 1; i <= this._total; i++)
            {
                if (i != this._id)
                {
                    this._counterpartyCommitments[i] = read[i];
                }
            }

            var send = new Dictionary<int, byte[]>();

            for (int i = 1; i <= this._total; i++)
            {
                if (i != this._id)
                {
                    send[i] = this._myPoint!.GetEncoded().Concat(
                        this._randomCommitment!.GetEncoded()
                    ).Concat(
                        Encoding.UTF8.GetBytes(this._zkPoK!.ToString())
                    ).ToArray();
                }
            }

            return send;
        }

        public void Reconstruct(Dictionary<int, byte[]> read)
        {
            var points = new List<ECPoint>();

            for (var i = 1; i < this._total; i++)
            {
                if (this._id == i)
                {
                    points.Add(this._myPoint!);
                }
                else
                {
                    var counterpartyPoint =
                        new byte[this._myPoint!.GetEncoded().Length];
                    var counterpartyECCommitment =
                        new byte[this._myPoint.GetEncoded().Length];
                    var counterpartyZKPoK =
                        new byte[
                            read[i].Length - (counterpartyPoint.Length * 2)
                        ];
                    
                    counterpartyPoint = read[i].Take(counterpartyPoint.Length)
                        .ToArray();
                    counterpartyECCommitment = read[i]
                        .Skip(counterpartyPoint.Length)
                        .Take(counterpartyPoint.Length).ToArray();
                    counterpartyZKPoK = read[i]
                        .Skip(counterpartyPoint.Length * 2).ToArray();
                    

                    points
                        .Add(this._param.Curve.DecodePoint(counterpartyPoint));
                    var digest = new Sha3Digest();
                    var counterpartyPointConcatRandomECPoint =
                        counterpartyPoint.Concat(counterpartyECCommitment)
                            .ToArray();
                    var challenge = new byte[digest.GetDigestSize()];
                    digest.BlockUpdate(
                        counterpartyPointConcatRandomECPoint,
                        0,
                        counterpartyPointConcatRandomECPoint.Length);
                    digest.DoFinal(challenge, 0);

                    var proof = this._point.Multiply(
                        new BigInteger(
                            Encoding.UTF8.GetString(counterpartyZKPoK)
                        )
                    );
                    // z = myScalar * challenge + randomECScalar
                    var check = this._param.Curve
                        .DecodePoint(counterpartyECCommitment)
                        .Add(
                            this._param.Curve.DecodePoint(counterpartyPoint)
                                .Multiply(new BigInteger(challenge))
                        );
                    
                    if (!proof.Equals(check))
                    {
                        Console.WriteLine($"Party {i} send invalid ZKPoK");
                        return;
                    }

                    digest = new Sha3Digest();
                    var verifier = new byte[digest.GetDigestSize()];
                    var cpECPConcatZKPoK = counterpartyECCommitment.Concat(
                        counterpartyZKPoK
                    ).ToArray();
                    digest.BlockUpdate(
                        cpECPConcatZKPoK,
                        0,
                        cpECPConcatZKPoK.Length);
                    digest.DoFinal(verifier, 0);

                    if (!verifier
                        .SequenceEqual(this._counterpartyCommitments![i]))
                    {
                        Console.WriteLine($"Party {i} send false commitment");
                    }
                }
            }

            this.PublicKey = this._curve.Curve.Infinity;

            for (var i = 0; i < this._total - this._threshold - 1; i++)
            {
                var reconstructedSum = this._curve.Curve.Infinity;

                for (var j = 0; j < this._threshold; j++)
                {
                    var coefficientNumerator = BigInteger.One;
                    var coefficientDenominator = BigInteger.One;

                    for (var k = 0; k < this._threshold; k++)
                    {
                        if (j != k)
                        {
                            coefficientNumerator = coefficientNumerator
                                .Multiply(
                                    new BigInteger((i + k + 1).ToString())
                                );
                            coefficientDenominator = coefficientDenominator
                                .Multiply(
                                    new BigInteger((i + k + 1).ToString())
                                        .Subtract(new BigInteger(
                                            (i + j + 1).ToString()
                                        )
                                    )
                                );
                        }
                    }

                    var reconstructedFragment = points[i + j].Multiply(
                        coefficientNumerator.Divide(coefficientDenominator)
                    );

                    if (reconstructedSum.IsInfinity)
                    {
                        reconstructedSum = reconstructedFragment;
                    }
                    else
                    {
                        reconstructedSum = reconstructedSum.Add(
                            reconstructedFragment
                        );
                    }
                }

                if (this.PublicKey.IsInfinity)
                {
                    this.PublicKey = reconstructedSum.Normalize();
                }
                else if (!this.PublicKey.Equals(reconstructedSum.Normalize()))
                {
                    this.PublicKey = this._curve.Curve.Infinity;
                    Console.WriteLine($"Key mismatch");
                }
            }
        }

        public Dictionary<int, byte[]> Next(Dictionary<int, byte[]> read)
        {
            var output = new Dictionary<int, byte[]>();

            switch (this.State)
            {
            case Round.Initialized:
                output = this.SendFragments();
                this.State = Round.SendFragments;
                break;
            case Round.SendFragments:
                output = this.SendProofCommitments(read);
                this.State = Round.SendProofCommitments;
                break;
            case Round.SendProofCommitments:
                output = this.SendPointsWithProof(read);
                this.State = Round.SendPointsWithProof;
                break;
            case Round.SendPointsWithProof:
                this.Reconstruct(read);
                this.State = Round.Ready;
                break;
            }

            return output;
        }

        public enum Round
        {
            Initialized,
            SendFragments,
            SendProofCommitments,
            SendPointsWithProof,
            Reconstruct,
            Ready,
        }
    }
}
