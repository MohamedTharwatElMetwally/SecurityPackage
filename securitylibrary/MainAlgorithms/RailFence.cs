using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int key = 0;
            RailFence rf = new RailFence();
            while (key <= plainText.Length) {
                if (rf.Encrypt(plainText, key) == cipherText || rf.Decrypt(cipherText, key) == plainText)
                    return key;

                key++;
            }

            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();

            // Create the table of desired width
            List<List<char>> table = new List<List<char>>();
            for (int i = 0; i < key; i++)
                table.Add(new List<char>());

            // Fill the table row-wise
            // Place '-' for empty places
            int lettersInRow = (int)Math.Ceiling((double)cipherText.Length / key);
            int ctIndex = 0;
            for (int i = 0; i < table.Count; i++)
                for (int j = 0; j < lettersInRow; j++, ctIndex++)
                    try { table[i].Add(cipherText[ctIndex]); }
                    catch (IndexOutOfRangeException) { table[i].Add('-'); }

            // Read the table column-wise
            string plain = "";
            for (int j = 0; j < lettersInRow; j++)
                for (int i = 0; i < table.Count; i++)
                    if (table[i][j] != '-')
                        plain += table[i][j];


            return plain;
        }

        public string Encrypt(string plainText, int key)
        {
            // Create the table of desired width
            List<List<char>> table = new List<List<char>>();
            for (int i = 0; i < key; i++)
                table.Add(new List<char>());

            // Fill the table column-wise
            // Place '-' for empty places
            int lettersInRow = (int)Math.Ceiling((double)plainText.Length / key);
            int ptIndex = 0;
            for (int j = 0; j < lettersInRow; j++)
                for (int i = 0; i < table.Count; i++, ptIndex++)
                    try { table[i].Add(plainText[ptIndex]); }
                    catch (IndexOutOfRangeException) { table[i].Add('-'); }

            // Read the table row-wise
            string cipher = "";
            for (int i = 0; i < table.Count; i++)
                for (int j = 0; j < lettersInRow; j++)
                    if (table[i][j] != '-')
                        cipher += table[i][j];

            return cipher;
        }
    }
}
