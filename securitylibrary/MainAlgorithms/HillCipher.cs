using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    /// 

    struct Position2D
    {
        public int x;
        public int y;

        public Position2D(int x, int y)
        {
            this.x = x;
            this.y = y;
        }
    }

    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            // throw new NotImplementedException();

            List<int> key = new List<int>();

            for (int i = 0; i < 26; i++)
                for (int j = 0; j < 26; j++)
                    for (int k = 0; k < 26; k++)
                        for (int l = 0; l < 26; l++)
                        {
                            key.Add(i);
                            key.Add(j);
                            key.Add(k);
                            key.Add(l);
                            if (AreEqual(Encrypt(plainText, key), cipherText) && AreEqual(Decrypt(cipherText, key), plainText))
                                return key;
                            key.Clear();
                        }

            throw new InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // throw new NotImplementedException();

            int m = (int)Math.Sqrt((double)key.Count());

            while (cipherText.Count() % m != 0)
                cipherText.Add((int)'x'); // add x

            int[,] keyInverse = InverseMatrix(Convert2D(key, m, m, 0));
            int[,] cipherText_2d = Convert2D(cipherText, m, cipherText.Count / m, 1);
            int[,] plainText = new int[m, cipherText.Count / m];

            for (int plain_col = 0; plain_col < cipherText_2d.GetLength(1); plain_col++)
            {
                for (int key_row = 0; key_row < keyInverse.GetLength(0); key_row++)
                {
                    int sum = 0;
                    for (int i = 0; i < keyInverse.GetLength(1); i++)
                        sum += keyInverse[key_row, i] * cipherText_2d[i, plain_col];

                    while (sum < 0)
                        sum += 26;

                    plainText[key_row, plain_col] = sum % 26;
                }
            }

            return Convert1D(plainText, 1);
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            // throw new NotImplementedException();

            int m = (int)Math.Sqrt((double)key.Count());

            while (plainText.Count() % m != 0)
                plainText.Add((int)'x'); // add x

            int[,] key_2d = Convert2D(key, m, m, 0);
            int[,] plainText_2d = Convert2D(plainText, m, plainText.Count / m, 1);
            int[,] cipherText = new int[m, plainText.Count / m];

            for (int plain_col = 0; plain_col < plainText_2d.GetLength(1); plain_col++)
            {
                for (int key_row = 0; key_row < key_2d.GetLength(0); key_row++)
                {
                    int sum = 0;
                    for (int i = 0; i < key_2d.GetLength(1); i++)
                        sum += key_2d[key_row, i] * plainText_2d[i, plain_col];
                    cipherText[key_row, plain_col] = sum % 26;
                }
            }

            return Convert1D(cipherText, 1);
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            // throw new NotImplementedException();

            int m = (int)Math.Sqrt((double)plainText.Count());

            int[,] plainTextInverse = InverseMatrix(Convert2D(plainText, m, m, 1));
            int[,] cipherText_2d = Convert2D(cipherText, m, m, 1);
            int[,] key = new int[m, m];

            for (int plain_col = 0; plain_col < plainTextInverse.GetLength(1); plain_col++)
            {
                for (int key_row = 0; key_row < cipherText_2d.GetLength(0); key_row++)
                {
                    int sum = 0;
                    for (int i = 0; i < cipherText_2d.GetLength(1); i++)
                        sum += cipherText_2d[key_row, i] * plainTextInverse[i, plain_col];
                    key[key_row, plain_col] = sum % 26;
                }
            }

            return Convert1D(key, 0);
        }


        public int[,] InverseMatrix(int[,] key)
        {

            int m = key.GetLength(0), det;

            //=================================
            //=========== inverse of 2x2 matrix
            //=================================

            if (m == 2)
            {
                det = key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0];

                // raise error if the key has no inverse
                int tmp = det;
                while (tmp < 0) tmp += 26;
                if (tmp == 0 || GCD(tmp, 26) != 1)
                    throw new Exception();

                tmp = key[0, 0];
                key[0, 0] = (int)((double)key[1, 1] / (double)det);
                key[1, 1] = (int)((double)tmp / (double)det);
                key[0, 1] *= (int)(-1.0 / (double)det);
                key[1, 0] *= (int)(-1.0 / (double)det);
                return key;
            }

            //=================================
            //=========== inverse of 3x3 matrix
            //=================================

            int[,] inversekey = new int[key.GetLength(0), key.GetLength(1)];

            // calculate det(k)
            det = key[0, 0] * (key[1, 1] * key[2, 2] - key[1, 2] * key[2, 1]) - key[0, 1] * (key[1, 0] * key[2, 2] - key[1, 2] * key[2, 0]) + key[0, 2] * (key[1, 0] * key[2, 1] - key[1, 1] * key[2, 0]);
            while (det < 0) det += 26;
            det %= 26;

            // raise error if the key has no inverse
            if (det == 0 || GCD(det, 26) != 1)
                throw new Exception();

            // calculate b
            double b, c = 1;
            while ((26.0 * c + 1.0) % det != 0) c++;
            b = (26.0 * c + 1.0) / (double)det;


            // update the key elements

            int[,] tmpkey = new int[m, m];
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    tmpkey[i, j] = key[i, j];

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    List<Position2D> det_elements = new List<Position2D>();
                    for (int row = 0; row < m; row++)
                    {
                        if (row == i) continue;
                        for (int col = 0; col < m; col++)
                        {
                            if (col == j) continue;
                            det_elements.Add(new Position2D(row, col));
                        }
                    }

                    key[i, j] = (int)b * (int)Math.Pow(-1, i + j) * (tmpkey[det_elements[0].x, det_elements[0].y] * tmpkey[det_elements[3].x, det_elements[3].y] - tmpkey[det_elements[1].x, det_elements[1].y] * tmpkey[det_elements[2].x, det_elements[2].y]);
                    while (key[i, j] < 0) key[i, j] += 26;
                    key[i, j] %= 26;
                }
            }


            // transpose
            int[,] keyTranspose = new int[m, m];
            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    keyTranspose[j, i] = key[i, j];

            return keyTranspose;
        }

        public bool AreEqual(List<int> list1, List<int> list2)
        {
            if (list1.Count != list2.Count)
                return false;

            for (int i = 0; i < list1.Count; i++)
                if (list1[i] != list2[i])
                    return false;

            return true;
        }

        public int GCD(int a, int b)
        {
            while (a != 0 && b != 0)
                if (a > b) a %= b;
                else b %= a;

            if (a == 0) return b;
            else return a;
        }

        public int[,] Convert2D(List<int> list, int rows, int cols, int dimension)
        {
            int[,] matrix = new int[rows, cols];

            int r = 0, c = 0;
            if (dimension == 0)  // fill row by row
            {
                for (int i = 0; i < list.Count; i++)
                {
                    matrix[r, c] = list[i];
                    c++;
                    if (c == cols)
                    {
                        r++;
                        c = 0;
                    }
                }
            }
            else   // fill col by col
            {
                for (int i = 0; i < list.Count; i++)
                {
                    matrix[r, c] = list[i];
                    r++;
                    if (r == rows)
                    {
                        c++;
                        r = 0;
                    }
                }
            }

            return matrix;
        }

        public List<int> Convert1D(int[,] matrix, int dimension)
        {
            List<int> list = new List<int>();

            if (dimension == 0) // scan row by row
            {
                for (int row = 0; row < matrix.GetLength(0); row++)
                    for (int col = 0; col < matrix.GetLength(1); col++)
                        list.Add(matrix[row, col]);
            }
            else // scan col by col
            {
                for (int col = 0; col < matrix.GetLength(1); col++)
                    for (int row = 0; row < matrix.GetLength(0); row++)
                        list.Add(matrix[row, col]);
            }

            return list;
        }

    }
}
