using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            // throw new NotImplementedException();

            return (int)ModularBinaryExponentiation(M, e, p * q);   // C = M^e % n, where n = p * q
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            // throw new NotImplementedException();

            return (int)ModularBinaryExponentiation(C, ModInverse2(e, (p - 1) * (q - 1)), p * q);    // M = C^d % n, where n = p * q, d = e^-1 % Alpha(n) and Alpha(n) = (p-1) * (q-1)  
        }

        public long ModulusMul(long x, long y, long m)
        {
            return ((x % m) * (y % m)) % m;
        }

        public long ModularBinaryExponentiation(long num, long exp, long mod)
        {
            long result = 1;
            while (exp > 0)
            {
                if (exp % 2 != 0) result = ModulusMul(result, num, mod);
                exp /= 2;
                num = ModulusMul(num, num, mod);
            }
            return result;
        }


        public long ModInverse2(int A, int M)
        {
            ExtendedEuclid extendedEuclid = new ExtendedEuclid();
            return extendedEuclid.GetMultiplicativeInverse(A, M);
        }
    }
}
