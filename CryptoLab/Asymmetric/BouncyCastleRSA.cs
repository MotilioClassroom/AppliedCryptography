// SPDX-License-Identifier: Unlicense

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Text;

namespace CryptoLab.Asymmetric;

public class BouncyCastleRSA : IRSACipher
{
    private AsymmetricCipherKeyPair keyPair; 
    private RsaPrivateCrtKeyParameters privateKey;
    private RsaKeyParameters publicKey;

    public BouncyCastleRSA(int keySizeBits = 4096)
    {
        
        var random = new SecureRandom();
        var keyGenerationParameters = new KeyGenerationParameters(random, keySizeBits);
        var rsaKeyPairGenerator = new RsaKeyPairGenerator();
        rsaKeyPairGenerator.Init(keyGenerationParameters);

        keyPair = rsaKeyPairGenerator.GenerateKeyPair();

        privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
        publicKey = (RsaKeyParameters)keyPair.Public;

    }

    public string GetPrivateKeyPEM()
    {

        var memoryStream = new MemoryStream();
        var streamWriter = new StreamWriter(memoryStream);

        var pemWriter = new PemWriter(streamWriter);
        pemWriter.WriteObject(privateKey);
        pemWriter.Writer.Flush();
        pemWriter.Writer.Close();

        var privatePem = Encoding.UTF8.GetString(memoryStream.ToArray());

        return privatePem;

    }

    public void ImportPrivateKeyPEM(string privateKeyPEM)
    {
        var pemReader = new PemReader(new StringReader(privateKeyPEM));
        var obj = pemReader.ReadObject();
        if (obj is AsymmetricCipherKeyPair pair && pair.Private != null)
        {
            privateKey = (RsaPrivateCrtKeyParameters)pair.Private;
        }
    }

    public string GetPublicKeyPEM()
    {
        var memoryStream = new MemoryStream();
        var streamWriter = new StreamWriter(memoryStream);

        var pemWriter = new PemWriter(streamWriter);
        pemWriter.WriteObject(publicKey);
        pemWriter.Writer.Flush();
        pemWriter.Writer.Close();

        var publicPem = Encoding.UTF8.GetString(memoryStream.ToArray());

        return publicPem;
    }

    public void ImportPublicKeyPEM(string publicKeyPEM)
    {
        var pemReader = new PemReader(new StringReader(publicKeyPEM));
        var obj = pemReader.ReadObject();
        if (obj is RsaKeyParameters pair)
        {
            publicKey = (RsaKeyParameters)obj;
        }

    }

    public byte[] Encrypt(byte[] data)
    {
        var cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), null);
        cipher.Init(true, publicKey);
        var cipherText = cipher.ProcessBlock(data, 0, data.Length);
        return cipherText;
    }

    public byte[] Decrypt(byte[] data)
    {
        var cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), null);
        cipher.Init(false, privateKey);
        var plainText = cipher.ProcessBlock(data, 0, data.Length);
        return plainText;

    }

    public byte[] SignData(byte[] data)
    {
        var signer = SignerUtilities.GetSigner("SHA-256withRSA");
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        var signature = signer.GenerateSignature();
        return signature;
    }

    public bool VerifyData(byte[] data, byte[] signature)
    {
        var verifier = SignerUtilities.GetSigner("SHA-256withRSA");
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }
}
