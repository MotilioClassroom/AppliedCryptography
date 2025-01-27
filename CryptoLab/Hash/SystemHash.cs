// SPDX-License-Identifier: Unlicense

using System.Text;
using System.Security.Cryptography;
using static CryptoLab.IHash;


namespace CryptoLab.Hash;

public class SystemHash : IHash
{
    public string ComputeHash(byte[] data, Algorithm algorithm)
    {
        HashAlgorithm hashAlgorithm = algorithm switch
        {
            Algorithm.SHA256 => SHA256.Create(),
            Algorithm.SHA512 => SHA512.Create(),
            _ => throw new NotImplementedException(),
        };

        var hashedBytes = hashAlgorithm.ComputeHash(data);

        return Convert.ToHexString(hashedBytes);
    }

    public string ComputeHash(string data, Algorithm algorithm)
    {
        return ComputeHash(Encoding.UTF8.GetBytes(data), algorithm);
    }
}
