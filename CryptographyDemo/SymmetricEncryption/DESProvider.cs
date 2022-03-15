using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.SymmetricEncryption
{
    /// <summary>
    /// 注：DES加密是所有对称加密中强度最弱的
    /// </summary>
    public class DESProvider
    {
        /// <summary>
        /// 定义16进制的字节向量  IV
        /// </summary>
        private readonly static byte[] IVKeys = { 0x13, 0x24, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

        /// <summary>
        /// 编码类型
        /// </summary>
        private readonly Encoding _encoding;

        public DESProvider(Encoding encoding)
        {
            _encoding = encoding;
        }

        /// <summary>
        /// 创建DES加密  需要提供加密密钥  对称加密加密解密的密钥相同
        /// </summary>
        /// <param name="pwd">需要进行加密的字符串</param>
        /// <param name="signKey">提供一个加密密钥，长度8位</param>
        /// <returns>加密成功返回密文，失败返回明文+错误信息</returns>
        public string CreateDESEncrypt(string pwd, string signKey)
        {
            try
            {
                byte[] rgbKey = _encoding.GetBytes(signKey.Substring(0, 8));
                byte[] rgbIV = IVKeys;
                byte[] inputByteArray = _encoding.GetBytes(pwd);
                DESCryptoServiceProvider dCSP = new DESCryptoServiceProvider();
                MemoryStream mStream = new MemoryStream();
                CryptoStream cStream = new CryptoStream(mStream, dCSP.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                cStream.Write(inputByteArray, 0, inputByteArray.Length);
                cStream.FlushFinalBlock();
                return Convert.ToBase64String(mStream.ToArray());
            }
            catch (Exception ex)
            {
                return pwd + "=>" + ex;
            }
        }

        /// <summary>
        /// 创建DES解密  需要提供与加密密钥相同的密钥
        /// </summary>
        /// <param name="encryptSource">机密后的密文</param>
        /// <param name="decryptKey">与加密使用的相同密钥</param>
        /// <returns>解密成功返回明文，失败返回密文+错误信息</returns>
        public string CreateDESDecrypt(string encryptSource, string decryptKey)
        {
            try
            {
                byte[] rgbKey = _encoding.GetBytes(decryptKey);
                byte[] rgbIV = IVKeys;
                byte[] inputByteArray = Convert.FromBase64String(encryptSource);
                DESCryptoServiceProvider DCSP = new DESCryptoServiceProvider();
                MemoryStream mStream = new MemoryStream();
                CryptoStream cStream = new CryptoStream(mStream, DCSP.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                cStream.Write(inputByteArray, 0, inputByteArray.Length);
                cStream.FlushFinalBlock();
                return _encoding.GetString(mStream.ToArray());
            }
            catch (Exception ex)
            {
                return encryptSource + "=>" + ex;
            }
        }
    }
}
