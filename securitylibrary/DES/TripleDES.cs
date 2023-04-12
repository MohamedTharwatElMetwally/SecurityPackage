﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        static List<int> shift_list = new List<int> { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        static List<int> IP_1 = new List<int> { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
        static List<int> IP = new List<int> { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
        static List<int> PC_1 = new List<int> { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
        static List<int> P = new List<int> { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
        static List<int> EB = new List<int> { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
        static List<int> PC_2 = new List<int> { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
        static int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        static int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        static int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        static int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        static int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        static int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        static int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        static int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
        static string convert_integer_to_binaryString(int n)
        {
            string binaryString = Convert.ToString(n, 2);
            return binaryString.PadLeft(4, '0');
        }

        static string do_permutation(string lst, List<int> convert_list)
        {
            string result = "";
            foreach (var x in convert_list)
                result += lst[x - 1];
            return result;
        }

        static string left_circular_shift(string lst, int number_of_shifts)
        {
            string result = lst;
            result = result.Remove(0, number_of_shifts);
            result += lst.Substring(0, number_of_shifts);
            return result;

        }
        static string do_XOR(string lst_1, string lst_2)
        {
            string result = "";
            for (int i = 0; i < lst_1.Length; i++)
                if (lst_1[i] == lst_2[i])
                    result += '0';
                else result += '1';
            return result;
        }
        static int convert_binaryString_to_integer(string s)
        {
            int result = Convert.ToInt32(s, 2);
            return result;
        }

        static string deal_with_row_column(string row, string column, int cnt)
        {
            int cur_number = 0;
            if (cnt == 1)
                cur_number = s1[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];
            else if (cnt == 2)
                cur_number = s2[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];
            else if (cnt == 3)
                cur_number = s3[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];
            else if (cnt == 4)
                cur_number = s4[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];
            else if (cnt == 5)
                cur_number = s5[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];
            else if (cnt == 6)
                cur_number = s6[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];
            else if (cnt == 7)
                cur_number = s7[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];
            else
                cur_number = s8[convert_binaryString_to_integer(row), convert_binaryString_to_integer(column)];

            string bin_str = convert_integer_to_binaryString(cur_number);
            return bin_str;
        }
        static string applay_S_box(string lst)
        {
            string result = "";
            int cnt = 0;
            for (int i = 0; i + 5 < lst.Length; i += 6)
            {
                cnt++;
                string row = lst[i].ToString();
                row += lst[i + 5];
                string column = lst[i + 1].ToString();
                column += lst[i + 2];
                column += lst[i + 3];
                column += lst[i + 4];
                string bin_str = deal_with_row_column(row, column, cnt);
                foreach (var x in bin_str)
                    result += x;
            }
            return result;
        }

        static string do_XOR_right(List<string> PC_2_list, int num_of_round, string right_side, bool flag)
        {
            string result = "";
            if (flag)
            {
                for (int i = 0; i < right_side.Length; i++)
                    if (PC_2_list[num_of_round][i] == right_side[i])
                        result += "0";
                    else
                        result += "1";
            }
            else
            {
                for (int i = 0; i < right_side.Length; i++)
                    if (PC_2_list[PC_2_list.Count - 1 - num_of_round][i] == right_side[i])
                        result += "0";
                    else
                        result += "1";
            }

            return result;
        }

        static string do_DES(string text, string key, bool flag)
        {
            string binaryplainText = Convert.ToString(Convert.ToInt64(text, 16), 2).PadLeft(64, '0');
            string binaryKey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            string bit_block_64 = do_permutation(binaryplainText, IP);
            string key_after_pc_1 = do_permutation(binaryKey, PC_1);
            string C_side = key_after_pc_1.Substring(0, 28);
            string D_side = key_after_pc_1.Substring(28, 28);
            List<string> C_list = new List<string>();
            List<string> D_list = new List<string>();
            C_list.Add(C_side);
            D_list.Add(D_side);
            for (int i = 0; i < 16; i++)
            {
                C_side = left_circular_shift(C_side, shift_list[i]);
                D_side = left_circular_shift(D_side, shift_list[i]);
                C_list.Add(C_side);
                D_list.Add(D_side);
            }
            List<string> C_plus_D = new List<string>();

            for (int i = 0; i < D_list.Count; i++)
                C_plus_D.Add(C_list[i] + D_list[i]);

            List<string> PC_2_list = new List<string>();
            for (int i = 1; i < C_plus_D.Count; i++)
                PC_2_list.Add(do_permutation(C_plus_D[i], PC_2));
            List<string> left_list = new List<string>();
            List<string> right_list = new List<string>();
            string left_side = bit_block_64.Substring(0, 32);
            string right_side = bit_block_64.Substring(32, 32);
            left_list.Add(left_side);
            right_list.Add(right_side);
            for (int i = 0; i < 16; i++)
            {
                left_list.Add(right_side);
                right_side = do_permutation(right_side, EB);
                right_side = do_XOR_right(PC_2_list, i, right_side, flag);
                right_side = applay_S_box(right_side);
                right_side = do_permutation(right_side, P);
                right_side = do_XOR(right_side, left_list[i]);
                right_list.Add(right_side);
            }
            string resOfSwap = right_list[16] + left_list[16];
            resOfSwap = do_permutation(resOfSwap, IP_1);
            string result = "0x" + Convert.ToInt64(resOfSwap, 2).ToString("X").PadLeft(16, '0');
            return result;
        }
        public string Decrypt(string cipherText, List<string> key)
        {
            string answer = "";
            answer = do_DES(cipherText, key[1], false);
            answer = do_DES(answer, key[0], true);
            answer = do_DES(answer, key[1], false);
            return answer;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string answer = "";
            answer = do_DES(plainText, key[0], true);
            answer = do_DES(answer, key[1], false);
            answer = do_DES(answer, key[0], true);
            return answer;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
