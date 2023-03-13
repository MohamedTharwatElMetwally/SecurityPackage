using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        // REFERENCE: https://www.chadgolden.com/blog/finding-all-the-permutations-of-an-array-in-c-sharp
        static IList<IList<int>> Permute(int[] nums) {
            var list = new List<IList<int>>();
            return DoPermute(nums, 0, nums.Length - 1, list);
        }

        static IList<IList<int>> DoPermute(int[] nums, int start, int end, IList<IList<int>> list) {
            if (start == end) {
                // We have one of our possible n! solutions,
                // add it to the list.
                list.Add(new List<int>(nums));
            } else {
                for (var i = start; i <= end; i++) {
                    Swap(ref nums[start], ref nums[i]);
                    DoPermute(nums, start + 1, end, list);
                    Swap(ref nums[start], ref nums[i]);
                }
            }

            return list;
        }

        static void Swap(ref int a, ref int b) {
            var temp = a;
            a = b;
            b = temp;
        }
        // -------------------------------------------- END ---------------------------------------------

        // NEWLY ADDED (NOT INCLUDED IN BASIC SECURITY PACKAGE)
        private IList<IList<int>> GetLists(List<int> key) {
            return Permute(key.ToArray());
        }
        // ----------------------- END ------------------------

        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower(); cipherText = cipherText.ToLower();

            List<int> key = new List<int>();

            for (int temp = 1; temp <= plainText.Length; temp++) {
                key.Add(temp);

                IList<IList<int>> lists = GetLists(key);

                foreach (var list in lists) {
                    Columnar columnar = new Columnar();
                    if (columnar.Encrypt(plainText, (List<int>)list) == cipherText || columnar.Decrypt(cipherText, (List<int>)list) == plainText) {
                        return (List<int>)list;
                    }
                }
            }
            
            throw new Exception();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // Create the table of desired height
            int nRows = (int)Math.Ceiling((double)cipherText.Length / key.Count);
            List<List<char>> table = new List<List<char>>();
            for (int i = 0; i < key.Count; i++)
                table.Add(new List<char>());

            // Fill the table column-wise with-respect-to key indices
            // Place '-' for empty places
            int ctIndex = 0;
            for (int i = 0; i < table.Count; i++)
                for (int j = 0; j < nRows; j++, ctIndex++)
                    try { table[key.IndexOf(i + 1)].Add(cipherText[ctIndex]); }
                    catch (IndexOutOfRangeException) { table[key.IndexOf(i + 1)].Add('-'); }

            // Read the table row-wise
            string plain = "";
            for (int j = 0; j < nRows; j++)
                for (int i = 0; i < table.Count; i++)
                    if (table[i][j] != '-')
                        plain += table[i][j];

            return plain;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            // Create the table of desired height
            int nRows = (int)Math.Ceiling((double)plainText.Length / key.Count);
            List<List<char>> table = new List<List<char>>();
            for (int i = 0; i < nRows; i++)
                table.Add(new List<char>());

            // Fill the table row-wise
            // Place '-' for empty places
            int ptIndex = 0;
            for (int i = 0; i < table.Count; i++)
                for (int j = 0; j < key.Count; j++, ptIndex++)
                    try { table[i].Add(plainText[ptIndex]); }
                    catch (IndexOutOfRangeException) { table[i].Add('-'); }

            // Read the table column-wise with-respect-to key indices
            string cipher = "";
            for (int i = 0; i < key.Count; i++)
                for (int j = 0; j < table.Count; j++)
                    if (table[j][key.IndexOf(i + 1)] != '-')
                        cipher += table[j][key.IndexOf(i + 1)];

            return cipher;
        }
    }
}
