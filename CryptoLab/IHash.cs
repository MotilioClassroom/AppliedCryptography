using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLab
{
    public interface IHash
    {
        string Hash(byte[] data);

        string Hash(string data);

    }
}
