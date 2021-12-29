using CryptographyDemo.Enums;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace CryptographyDemo.HashAlgorithm.SM3
{
    /// <summary>
    /// SM3算法(10进制的ASCII)  
    /// 在SHA-256基础上改进实现的一种算法  
    /// 对标国际MD5算法和SHA算法
    /// </summary>
    public static class SM3Crypto
    {
        /// <summary>
        /// sm3加密(使用自定义密钥)
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ToSM3byte(string data, string key)
        {
            byte[] msg1 = Encoding.Default.GetBytes(data);
            byte[] key1 = Encoding.Default.GetBytes(key);

            KeyParameter keyParameter = new KeyParameter(key1);
            SM3Provider sm3 = new SM3Provider();

            HMac mac = new HMac(sm3);//带密钥的杂凑算法
            mac.Init(keyParameter);
            mac.BlockUpdate(msg1, 0, msg1.Length);
            byte[] result = new byte[mac.GetMacSize()];

            mac.DoFinal(result, 0);
            var hexResult = Hex.Encode(result);
            return Convert.ToBase64String(hexResult);
        }

        /// <summary>
        /// sm3加密
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ToSM3byte(this string data)
        {
            var msg = data.ToHexByte();//把字符串转成16进制的ASCII码 
            SM3Provider sm3 = new SM3Provider();
            sm3.BlockUpdate(msg, 0, msg.Length);
            byte[] md = new byte[sm3.GetDigestSize()];//SM3算法产生的哈希值大小
            sm3.DoFinal(md, (int)Scattered.None);
            var hexResult = Hex.Encode(md);
            return Convert.ToBase64String(hexResult);
        }

        /// <summary>
        /// 字符串转16进制字节数组
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] ToHexByte(this string data)
        {
            byte[] msg1 = Encoding.Default.GetBytes(data);
            string hexString = BytesToHexString(msg1);
            byte[] returnBytes = new byte[hexString.Length / (int)Scattered.Half];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * (int)Scattered.Half, (int)Scattered.Half), 10);
            return returnBytes;
        }

        /// <summary>
        /// byte[]数组转16进制字符串
        /// </summary>
        /// <param name="input">byte[]数组</param>
        /// <returns>16进制字符串</returns>
        public static string BytesToHexString(byte[] input)
        {
            StringBuilder hexString = new StringBuilder(64);

            for (int i = 0; i < input.Length; i++)
            {
                hexString.Append(String.Format("{0:X2}", input[i]));
            }
            return hexString.ToString();
        }
    }
}
