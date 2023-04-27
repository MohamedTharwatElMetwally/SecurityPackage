using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 
        static long Fast_P(long bas, long exp, long mod)
        {
            long ans = 1;
            while (exp > 0)
            {
                if ((exp & 1) == 1)
                    ans = (ans * bas) % mod;
                exp /= 2;
                bas = (bas * bas) % mod;
            }
            return ans;
        }

        static long mod_inverse(long x, long mod)
        {
            return Fast_P(x, mod - 2,mod);
        }
        

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)   // k => random number < q
        {
            
            long c1 = Fast_P(alpha, k, q);
            long  c2 = (m * Fast_P(y, k, q)) % q;
            List<long> ans = new List<long>();
            ans.Add(c1);
            ans.Add(c2);
            Console.WriteLine(c1 + " " + c2);
            return ans;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            long s = Fast_P(c1, x, q);
            long m = (c2 * mod_inverse(s, q)) % q;
            return (int)m;

        }
    }
}
