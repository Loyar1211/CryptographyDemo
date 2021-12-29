using System;
using System.Text;

namespace CryptographyDemo.Utils
{
    public unsafe static class PublicTools
    {
        #region 公共方法

        /// <summary>
        /// 获取盐 字节
        /// </summary>
        /// <param name="parm">任意字符串</param>
        /// <returns></returns>
        public unsafe static byte[] GeneralSlat(string parm, string SaltKey) => Encoding.UTF8.GetBytes(MixedString(parm, SaltKey));

        /// <summary>
        /// 零散处理
        /// </summary>
        /// <param name="bytes">散列字节</param>
        /// <param name="ScatteredInterval">散列规律</param>
        /// <returns></returns>
        public unsafe static string ScatteredData(byte[] bytes, int ScatteredInterval)
        {
            byte[] buffer = new byte[bytes.Length / ScatteredInterval];
            int I = 0;
            var J = 0;
            while (I < bytes.Length)
            {
                J++;
                I += 2;
                if (I == bytes.Length) break;
                Buffer.SetByte(buffer, I - J - 1, bytes[I]);
            }
            return Convert.ToBase64String(buffer);
        }

        /// <summary>
        /// 混合两个字符串的数值，穿插混合
        /// </summary>
        /// <param name="str1">字符串1</param>
        /// <param name="str2">字符串2</param>
        /// <returns></returns>
        public unsafe static string MixedString(string str1, string str2)
        {
            string[] mixedArr = new string[str1.Length + str2.Length + 1];
            var str1Identity = 0;
            var str2Identity = 1;
            foreach (var item in str1)
            {
                mixedArr.SetValue(item.ToString(), str1Identity);
                if (str1Identity < str2.Length)
                    str1Identity += 2;
                else
                    str1Identity++;
            }
            foreach (var item in str2)
            {
                mixedArr.SetValue(item.ToString(), str2Identity);
                if (str2Identity < str1.Length)
                    str2Identity += 2;
                else
                    str2Identity++;
            }
            return string.Join(string.Empty, mixedArr);
        }
        #endregion
    }
}
