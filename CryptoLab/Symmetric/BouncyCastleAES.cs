using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLab.Symmetric;

public class BouncyCastleAES : ISymmetric
{
    public byte[] CreateRandomByteArray(int size)
    {
        var random = new SecureRandom();
        byte[] bytes = new byte[size];
        random.NextBytes(bytes);
        return bytes;
    }

    public byte[] DeriveKey(string password, byte[] salt, int iterations, int keySize)
    {
        var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
        pdb.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), salt, iterations);
        var key = (KeyParameter)pdb.GenerateDerivedMacParameters(keySize);
        return key.GetKey();
    }

    public byte[] Encrypt(byte[] key, byte[] iv, byte[] plainData)
    {
        var keyParamWithIV = new ParametersWithIV(new KeyParameter(key), iv);

        IBlockCipher symmetricBlockCipher = new AesEngine();
        IBlockCipherMode symmetricBlockMode = new CbcBlockCipher(symmetricBlockCipher);
        IBlockCipherPadding padding = new Pkcs7Padding();

        var cbcCipher = new PaddedBufferedBlockCipher(symmetricBlockMode, padding);
        cbcCipher.Init(true, keyParamWithIV);
        int blockSize = cbcCipher.GetBlockSize();

        var outputSize = cbcCipher.GetOutputSize(plainData.Length);
        byte[] cipherTextData = new byte[outputSize];

        int processLength = cbcCipher.ProcessBytes(plainData, 0, plainData.Length, cipherTextData, 0);

        int finalLength = cbcCipher.DoFinal(cipherTextData, processLength);

        byte[] finalCipherTextData = new byte[cipherTextData.Length - (blockSize - finalLength)];

        Array.Copy(cipherTextData, 0, finalCipherTextData, 0, finalCipherTextData.Length);

        return finalCipherTextData;
    }

    public byte[] Decrypt(byte[] key, byte[] iv, byte[] cipherData)
    {
        var keyParamWithIV = new ParametersWithIV(new KeyParameter(key), iv);

        IBlockCipher symmetricBlockCipher = new AesEngine();
        IBlockCipherMode symmetricBlockMode = new CbcBlockCipher(symmetricBlockCipher);
        IBlockCipherPadding padding = new Pkcs7Padding();

        var cbcCipher = new PaddedBufferedBlockCipher(symmetricBlockMode, padding);
        cbcCipher.Init(false, keyParamWithIV);
        int blockSize = cbcCipher.GetBlockSize();

        byte[] plainTextData = new byte[cbcCipher.GetOutputSize(cipherData.Length)];

        int processLength = cbcCipher.ProcessBytes(cipherData, 0, cipherData.Length, plainTextData, 0);

        int finalLength = cbcCipher.DoFinal(plainTextData, processLength);

        byte[] finalPlainTextData = new byte[plainTextData.Length - (blockSize - finalLength)];

        Array.Copy(plainTextData, 0, finalPlainTextData, 0, finalPlainTextData.Length);

        return finalPlainTextData;
    }

}
