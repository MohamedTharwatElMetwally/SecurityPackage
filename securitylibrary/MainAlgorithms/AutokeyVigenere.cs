using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char convert_Encrypt(char c1, char c2)
        {
            int x = c1 + (c2 - 97);
            if (x > 122)
                x = 97 + (x - 123);
            return (char)x;
        }
        char convert_Decrypt(char c1, char c2)
        {
            int x = '-';
            if (c2 >= c1)
                x = (c2 - c1) + 97;
            else
                x = (123 - c1) + c2;
            return (char)x;
        }
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i =0;i < plainText.Length; i++)
                key += convert_Decrypt(plainText[i], cipherText[i]);
            string prefix = "", suffix = "";
            for(int i = 0; i < plainText.Length; i++)
            {
                suffix = key[plainText.Length - i - 1] + suffix;
                prefix += plainText[i];
                if (suffix == prefix)
                {
                    key = key.Remove(plainText.Length - i - 1);
                    return key;
                }
            }
            return "";
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plan = "";
            int size = cipherText.Length;
            int key_pointer = 0;
            while (key.Length != size)
                key += convert_Decrypt(key[key_pointer], cipherText[key_pointer++]);
            for (int i = 0; i < size; i++)
                plan += convert_Decrypt(key[i], cipherText[i]);
            return plan;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            int size = plainText.Length;
            int key_pointer = 0;
            while (key.Length != plainText.Length)
                key += plainText[key_pointer++ % size];
            for (int i = 0; i < size; i++)
                cipher += convert_Encrypt(plainText[i], key[i]);
            return cipher;
        }
    }
}
