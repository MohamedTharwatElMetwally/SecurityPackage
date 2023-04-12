using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public byte[,] KeyExpansion(byte[,] cipherKey)
        {
            byte[,] keyExpansion = new byte[4, 44];

            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    keyExpansion[i, j] = cipherKey[i, j];

            for (int col = 4; col < 44; col++)
            {
                if (col % 4 == 0)
                {
                    byte[] word = new byte[4];

                    // RotWord
                    word[3] = keyExpansion[0, col - 1];
                    for (int i = 0; i < 3; i++)
                        word[i] = keyExpansion[i + 1, col - 1];

                    // SubBytes
                    for (int i = 0; i < 4; i++)
                    {
                        string wordstr = Convert.ToString(word[i], 16);
                        int IndexRow, IndexCol;
                        if (wordstr.Length < 2)
                        {
                            IndexRow = 0;
                            IndexCol = Convert.ToInt32(wordstr[0].ToString(), 16);
                        }
                        else
                        {
                            IndexRow = Convert.ToInt32(wordstr[0].ToString(), 16);
                            IndexCol = Convert.ToInt32(wordstr[1].ToString(), 16);
                        }
                        word[i] = AESUtilities.SBox[IndexRow, IndexCol];
                    }

                    // XOR 
                    for (int i = 0; i < 4; i++)
                    {
                        string tmp = Convert.ToString(keyExpansion[i, col - 4] ^ word[i] ^ AESUtilities.Rcon[i, col / 4 - 1], 16);
                        keyExpansion[i, col] = Convert.ToByte(tmp, 16);
                    }
                }
                else
                {
                    // XOR
                    for (int i = 0; i < 4; i++)
                    {
                        string tmp = Convert.ToString(keyExpansion[i, col - 1] ^ keyExpansion[i, col - 4], 16);
                        keyExpansion[i, col] = Convert.ToByte(tmp, 16);
                    }
                }
            }

            return keyExpansion;
        }

        public byte[,] GetRoundKey(byte[,] keyExpansion, int round)
        {
            byte[,] key = new byte[4, 4];
            for (int col = round * 4; col < round * 4 + 4; col++)
                for (int i = 0; i < 4; i++)
                    key[i, col % 4] = keyExpansion[i, col];
            return key;
        }

        public void SubBytes(ref byte[,] plainText)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                {
                    string wordstr = Convert.ToString(plainText[i, j], 16);
                    int IndexRow, IndexCol;
                    if (wordstr.Length < 2)
                    {
                        IndexRow = 0;
                        IndexCol = Convert.ToInt32(wordstr[0].ToString(), 16);
                    }
                    else
                    {
                        IndexRow = Convert.ToInt32(wordstr[0].ToString(), 16);
                        IndexCol = Convert.ToInt32(wordstr[1].ToString(), 16);
                    }
                    plainText[i, j] = AESUtilities.SBox[IndexRow, IndexCol];
                }
        }

        public void InverseSubBytes(ref byte[,] cipherText)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                {
                    string wordstr = Convert.ToString(cipherText[i, j], 16);
                    int IndexRow, IndexCol;
                    if (wordstr.Length < 2)
                    {
                        IndexRow = 0;
                        IndexCol = Convert.ToInt32(wordstr[0].ToString(), 16);
                    }
                    else
                    {
                        IndexRow = Convert.ToInt32(wordstr[0].ToString(), 16);
                        IndexCol = Convert.ToInt32(wordstr[1].ToString(), 16);
                    }
                    cipherText[i, j] = AESUtilities.SBoxInverse[IndexRow, IndexCol];
                }
        }


        public void ShiftRows(ref byte[,] plainText)
        {
            for (int row = 1; row < 4; row++)
            {
                for (int times = 0; times < row; times++)
                {
                    byte temp = plainText[row, 0];
                    for (int i = 0; i < 3; i++) plainText[row, i] = plainText[row, i + 1];
                    plainText[row, 3] = temp;
                }
            }
        }

        public void InverseShiftRows(ref byte[,] cipherText)
        {
            for (int row = 1; row < 4; row++)
            {
                for (int times = 0; times < 4 - row; times++)
                {
                    byte temp = cipherText[row, 0];
                    for (int i = 0; i < 3; i++) cipherText[row, i] = cipherText[row, i + 1];
                    cipherText[row, 3] = temp;
                }
            }
        }

        public void MixColumns(ref byte[,] plainText)
        {
            byte[,] resultedMatrix = new byte[4, 4];

            for (int col_matrix = 0; col_matrix < 4; col_matrix++)
            {
                for (int row_galois = 0; row_galois < 4; row_galois++)
                {
                    byte[] xor = new byte[4];
                    for (int i = 0; i < 4; i++)
                        xor[i] = ByteMultiplication(plainText[i, col_matrix], (int)AESUtilities.GaloisField[row_galois, i]);
                    resultedMatrix[row_galois, col_matrix] = Convert.ToByte(xor[0] ^ xor[1] ^ xor[2] ^ xor[3]);
                }
            }
            plainText = resultedMatrix;
        }

        public void InverseMixColumns(ref byte[,] cipherText)
        {
            byte[,] resultedMatrix = new byte[4, 4];

            for (int col_matrix = 0; col_matrix < 4; col_matrix++)
            {
                for (int row_galois = 0; row_galois < 4; row_galois++)
                {
                    byte[] xor = new byte[4];
                    for (int i = 0; i < 4; i++)
                        xor[i] = ByteMultiplication(cipherText[i, col_matrix], (int)AESUtilities.GaloisFieldInverse[row_galois, i]);
                    resultedMatrix[row_galois, col_matrix] = Convert.ToByte(xor[0] ^ xor[1] ^ xor[2] ^ xor[3]);
                }
            }
            cipherText = resultedMatrix;
        }


        public byte MultiplyByteByTwo(byte input)
        {
            byte result = Convert.ToByte(input << 1 & 0xFF);
            if (input > 127)  // > 0x7f
                result = Convert.ToByte(result ^ 27);  // > 0x1b
            return result;
        }

        public byte ByteMultiplication(byte input, int times)
        {
            if (times == 1) return input;
            if (times == 2) return MultiplyByteByTwo(input);
            if (times == 3) return Convert.ToByte(MultiplyByteByTwo(input) ^ input);
            if (times > 3)
            {
                byte b1 = MultiplyByteByTwo(input);
                byte b2 = MultiplyByteByTwo(b1);
                byte b3 = MultiplyByteByTwo(b2);
                if (times == 9) return Convert.ToByte(b3 ^ input);
                if (times == 11) return Convert.ToByte(b3 ^ b1 ^ input);
                if (times == 13) return Convert.ToByte(b3 ^ b2 ^ input);
                if (times == 14) return Convert.ToByte(b3 ^ b2 ^ b1);
            }
            return input;
        }

        public void AddRoundKey(ref byte[,] State, byte[,] roundKey)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(State[i, j] ^ roundKey[i, j], 16);
                    State[i, j] = Convert.ToByte(tmp, 16);
                }
        }

        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            byte[,] CipherText = AESUtilities.ToByteArray(cipherText);
            byte[,] cipherKey = AESUtilities.ToByteArray(key);
            byte[,] keyExpansion = KeyExpansion(cipherKey);

            // Final Round
            AddRoundKey(ref CipherText, GetRoundKey(keyExpansion, 10));
            InverseShiftRows(ref CipherText);
            InverseSubBytes(ref CipherText);

            // 9 Main Rounds
            for (int round = 9; round > 0; round--)
            {
                AddRoundKey(ref CipherText, GetRoundKey(keyExpansion, round));
                InverseMixColumns(ref CipherText);
                InverseShiftRows(ref CipherText);
                InverseSubBytes(ref CipherText);
            }

            // Initial Round
            AddRoundKey(ref CipherText, cipherKey);

            return AESUtilities.ToString(CipherText);
        }

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            byte[,] PlainText = AESUtilities.ToByteArray(plainText);
            byte[,] cipherKey = AESUtilities.ToByteArray(key);
            byte[,] keyExpansion = KeyExpansion(cipherKey);

            // Initial Round
            AddRoundKey(ref PlainText, cipherKey);

            // 9 Main Rounds
            for (int round = 1; round <= 9; round++)
            {
                SubBytes(ref PlainText);
                ShiftRows(ref PlainText);
                MixColumns(ref PlainText);
                AddRoundKey(ref PlainText, GetRoundKey(keyExpansion, round));
            }

            // Final Round
            SubBytes(ref PlainText);
            ShiftRows(ref PlainText);
            AddRoundKey(ref PlainText, GetRoundKey(keyExpansion, 10));

            return AESUtilities.ToString(PlainText);
        }
    }
}
