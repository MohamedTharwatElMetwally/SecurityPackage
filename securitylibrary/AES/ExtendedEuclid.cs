using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            // throw new NotImplementedException();
            int x = 0, y = 0;
            int gcd = Extended_Euclid(number, baseN, ref x, ref y);
            if (gcd != 1) return -1;
            else return (x % baseN + baseN) % baseN;
        }

        public int Extended_Euclid(int a, int b, ref int x_prev, ref int y_prev)
        {
            if(b== 0)
            {
                x_prev = 1;
                y_prev = 0;
                return a;
            }
            int gcd = Extended_Euclid(b, a % b,ref y_prev,ref x_prev);
            y_prev -= a / b * x_prev;
            return gcd;
        }
    }
}
