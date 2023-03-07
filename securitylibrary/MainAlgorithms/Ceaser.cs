using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            String c = "";
            foreach (char l in plainText.ToLower())
            {
                int p_idx = alpha.IndexOf(char.ToUpper(l));

                int c_idx = (p_idx + key) % alpha.Length;


                c += (char)alpha[c_idx];
            }



            return c;
        }

        public string Decrypt(string cipherText, int key)
        {
            String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int p_idx = 0;
            String p = "";
            foreach (char l in cipherText)
            {

                int c_idx = alpha.IndexOf(char.ToUpper(l));

                int new_k = alpha.Length - key;

                p_idx = (c_idx + new_k) % alpha.Length;

                p += (char)alpha[p_idx];
            }
            return p.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int k = 0;

            int p_idx = alpha.IndexOf(char.ToUpper(plainText[0]));
            int c_idx = alpha.IndexOf(char.ToUpper(cipherText[0]));
            k = c_idx - p_idx;
            if (k > 0)
                return k;
            else if (k < 0) return k + alpha.Length;
            else return 0;
        }
    }
}

