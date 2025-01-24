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
        throw new NotImplementedException();
    }

    public byte[] DeriveKey(string password, byte[] salt, int iterations, int keySize)
    {
        throw new NotImplementedException();
    }

    public byte[] Encrypt(byte[] key, byte[] iv, byte[] plainData, byte[]? salt = null)
    {
        throw new NotImplementedException();
    }

    public byte[] Decrypt(byte[] key, byte[] iv, byte[] cipherData)
    {
        throw new NotImplementedException();
    }


}
