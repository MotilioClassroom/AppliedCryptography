using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLab
{
    public interface IAsymmetric
    {
        byte[] Encrypt(byte[] key, byte[] iv, byte[] data);

        byte[] Decrypt(byte[] key, byte[] iv, byte[] data);
    }
}
