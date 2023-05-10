using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.MD5
{
    public class MD5
    {
        static uint[] K = new uint[64] {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        static int[] s = new int[64] {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        };

       

        public string GetHash(string text)
        {
            uint AA = 0x67452301,BB = 0xefcdab89 , CC = 0x98badcfe,DD = 0x10325476;    
            byte[] Byte_Text = Encoding.UTF8.GetBytes(text);
            byte [] NEW_TEXT = new byte[Byte_Text.Length + 1 + (56 - ((Byte_Text.Length + 1) % 64)) % 64 + 8];
            Array.Copy(Byte_Text, NEW_TEXT, Byte_Text.Length);
            NEW_TEXT[Byte_Text.Length] = 0x80; 
            Array.Copy(BitConverter.GetBytes(Byte_Text.Length * 8), 0, NEW_TEXT, NEW_TEXT.Length - 8, 4);
            int size = NEW_TEXT.Length / 64;
            for (int i = 0; i < size ; i++)
            {
                uint[] M = new uint[16];
                for (int j = 0; j <= 15; j++)
                {
                    M[j] = BitConverter.ToUInt32(NEW_TEXT, (i * 64) + (j * 4));
                }

                uint a = AA, b = BB, c = CC, d = DD;
                uint F = 0;
                uint g = 0;
                for (uint cnt = 0; cnt < 64; cnt++)
                {
                    if (cnt <= 15)
                        F = (b & c) | (~b & d); 
                    else if (cnt >= 16 && cnt <= 31)
                        F = (d & b) | (~d & c);
                    else if (cnt >= 32 && cnt <= 47)
                        F = b ^ c ^ d;
                    else
                        F = c ^ (b | ~d);

                    if (cnt <= 15)
                        g = cnt;
                    else if (cnt >= 16 && cnt <= 31)
                        g = ((5 * cnt) + 1) % 16;
                    else if (cnt >= 32 && cnt <= 47)
                        g = ((3 * cnt) + 5) % 16;
                    else
                        g = (7 * cnt) % 16;
                   
                    var dt = d; 
                    d = c;
                    c = b;
                    uint X = ((a + F + K[cnt] + M[g]) << s[cnt]) | ((a + F + K[cnt] + M[g]) >> (32 - s[cnt]));
                    b += X;
                    a = dt;
                }

                AA = AA +  a;
                BB = BB + b;
                CC = CC +  c;
                DD = DD + d;
            }

            return String.Join("", BitConverter.GetBytes(AA).Select(y => y.ToString("x2")))
                + String.Join("", BitConverter.GetBytes(BB).Select(y => y.ToString("x2")))
                + String.Join("", BitConverter.GetBytes(CC).Select(y => y.ToString("x2")))
                + String.Join("", BitConverter.GetBytes(DD).Select(y => y.ToString("x2")));
        }
    }
}
