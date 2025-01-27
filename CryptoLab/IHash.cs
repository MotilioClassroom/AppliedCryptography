// SPDX-License-Identifier: Unlicense

namespace CryptoLab;

public interface IHash
{
    public enum Algorithm
    {
        SHA256,
        SHA512,
    }

    string ComputeHash(byte[] data, Algorithm algorithm);

    string ComputeHash(string data, Algorithm algorithm);

}
