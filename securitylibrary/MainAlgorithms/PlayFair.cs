using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();

            char[,] matrix = KeyMatrix(key);

            StringBuilder plainText = new StringBuilder();

            cipherText = cipherText.ToLower();

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                int row1 = -1, row2 = -1, col1 = -1, col2 = -1;

                for (int r = 0; r < 5; r++)
                {
                    for (int c = 0; c < 5; c++)
                    {
                        if (matrix[r, c] == cipherText[i] || matrix[r, c] == 'i' && cipherText[i] == 'j')
                        {
                            row1 = r;
                            col1 = c;
                        }
                        if (matrix[r, c] == cipherText[i + 1] || matrix[r, c] == 'i' && cipherText[i + 1] == 'j')
                        {
                            row2 = r;
                            col2 = c;
                        }
                    }
                }

                if (row1 == row2)
                {
                    plainText.Append(matrix[row1, (col1 - 1 + 5) % 5]);
                    plainText.Append(matrix[row2, (col2 - 1 + 5) % 5]);
                }
                else if (col1 == col2)
                {
                    plainText.Append(matrix[(row1 - 1 + 5) % 5, col1]);
                    plainText.Append(matrix[(row2 - 1 + 5) % 5, col2]);
                }
                else
                {
                    plainText.Append(matrix[row1, col2]);
                    plainText.Append(matrix[row2, col1]);
                }
            }

            if (plainText[plainText.Length - 1] == 'x')
                plainText.Remove(plainText.Length - 1, 1);

            for (int i = 0; i < plainText.Length - 2; i += 2)
                if (plainText[i] == plainText[i + 2] && plainText[i + 1] == 'x')
                    plainText.Remove(i-- + 1, 1);

            return plainText.ToString();
        }

        public string Encrypt(string plain_Text, string key)
        {
            // throw new NotImplementedException();

            char[,] matrix = KeyMatrix(key);

            StringBuilder cipherText = new StringBuilder();

            plain_Text = plain_Text.ToLower();
            StringBuilder plainText = new StringBuilder(plain_Text);

            for (int i = 0; i < plainText.Length; i += 2)
                if (i + 1 < plainText.Length && plainText[i] == plainText[i + 1])
                    plainText.Insert(i + 1, "x");

            if (plainText.Length % 2 != 0)
                plainText.Append('x');

            for (int i = 0; i < plainText.Length; i += 2)
            {
                int row1 = -1, row2 = -1, col1 = -1, col2 = -1;

                for (int r = 0; r < 5; r++)
                {
                    for (int c = 0; c < 5; c++)
                    {
                        if (matrix[r, c] == plainText[i] || matrix[r, c] == 'i' && plainText[i] == 'j')
                        {
                            row1 = r;
                            col1 = c;
                        }
                        if (matrix[r, c] == plainText[i + 1] || matrix[r, c] == 'i' && plainText[i + 1] == 'j')
                        {
                            row2 = r;
                            col2 = c;
                        }
                    }
                }

                if (row1 == row2)
                {
                    cipherText.Append(matrix[row1, (col1 + 1) % 5]);
                    cipherText.Append(matrix[row2, (col2 + 1) % 5]);
                }
                else if (col1 == col2)
                {
                    cipherText.Append(matrix[(row1 + 1) % 5, col1]);
                    cipherText.Append(matrix[(row2 + 1) % 5, col2]);
                }
                else
                {
                    cipherText.Append(matrix[row1, col2]);
                    cipherText.Append(matrix[row2, col1]);
                }
            }

            return cipherText.ToString();
        }

        public char[,] KeyMatrix(string key)
        {
            char[,] matrix = new char[5, 5];

            List<char> chars = new List<char>();
            for (int i = 0; i < 26; i++)
                chars.Add(Convert.ToChar(97 + i));

            key = key.ToLower();

            int row = 0, col = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (chars.Contains(key[i]))
                {
                    if (key[i] == 'i' && chars.Contains('j')) chars.Remove('j');
                    if (key[i] == 'j' && chars.Contains('i')) chars.Remove('i');
                    chars.Remove(key[i]);

                    if (key[i] == 'i' || key[i] == 'j')
                        matrix[row, col++] = 'i';
                    else
                        matrix[row, col++] = key[i];

                    if (col == 5)
                    {
                        row++;
                        col = 0;
                    }
                }
            }

            while (chars.Count > 0)
            {
                if (chars[0] == 'i' && chars.Contains('j')) chars.Remove('j');
                if (chars[0] == 'j' && chars.Contains('i')) chars.Remove('i');


                if (chars[0] == 'i' || chars[0] == 'j')
                    matrix[row, col++] = 'i';
                else
                    matrix[row, col++] = chars[0];

                chars.RemoveAt(0);

                if (col == 5)
                {
                    row++;
                    col = 0;
                }
            }

            return matrix;
        }
    }
}
