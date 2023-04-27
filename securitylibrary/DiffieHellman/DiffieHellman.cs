using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        static int Fast_P(int bas, int exp, int mod)
        {
            int ans = 1;
            while (exp > 0)
            {
                if ((exp & 1) == 1)
                    ans = (ans * bas) % mod;
                exp /= 2;
                bas = (bas * bas) % mod;
            }

            return ans;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int g = alpha;
            int prime = q;
            int private_1 = xa;
            int private_2 = xb;

            int A = Fast_P(g, private_1, prime);
            int B = Fast_P(g, private_2, prime);

            int secret_A = Fast_P(B, private_1, prime);

            List<int> result = new List<int>();

            result.Add(secret_A);
            result.Add(secret_A);
            return result;

        }
    }
}
