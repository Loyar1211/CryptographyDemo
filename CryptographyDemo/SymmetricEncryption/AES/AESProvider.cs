using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.SymmetricEncryption.AES
{
    public static class AESProvider
    {
        /// <summary>
        /// 临时向量，可以根据不同场景进行更改
        /// </summary>
        private readonly static byte[] _key1 = Encoding.UTF8.GetBytes("1111111111111111");

        #region AES加密 不分组，使用安全较低的方式ECB
        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="decryptString">AES密文</param>
        /// <param name="key">秘钥（44个字符）</param>
        /// <param name="ivString">向量（16个字符）</param>
        /// <returns></returns>
        public static string LowAES_Decrypt(string decryptString, string key, string ivString)
        {

            key = key.PadRight(32, ' ');
            RijndaelManaged aes = new RijndaelManaged();

            byte[] iv = Encoding.UTF8.GetBytes(ivString.Substring(0, 16));
            aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 32));
            aes.Mode = CipherMode.ECB;
            aes.IV = iv;///使用ECB其实是不需要初始化向量的
            aes.Padding = PaddingMode.PKCS7;  //


            ICryptoTransform rijndaelDecrypt = aes.CreateDecryptor();
            byte[] inputData = Convert.FromBase64String(decryptString);
            byte[] xBuff = rijndaelDecrypt.TransformFinalBlock(inputData, 0, inputData.Length);

            return Encoding.UTF8.GetString(xBuff);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="encriyptString">要被加密的字符串</param>
        /// <param name="key">秘钥（44个字符）</param>
        /// <param name="ivString">向量长度（16个字符）</param>
        /// <returns></returns>
        public static string LowAES_Encrypt(string encriyptString, string key, string ivString)
        {
            key = key.PadRight(32, ' ');
            SymmetricAlgorithm aes = new RijndaelManaged();

            byte[] iv = Encoding.UTF8.GetBytes(ivString.Substring(0, 16));


            aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 32));
            aes.Mode = CipherMode.ECB;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7; //


            ICryptoTransform rijndaelEncrypt = aes.CreateEncryptor();
            byte[] inputData = Encoding.UTF8.GetBytes(encriyptString);
            byte[] encryptedData = rijndaelEncrypt.TransformFinalBlock(inputData, 0, inputData.Length);

            return Convert.ToBase64String(encryptedData);
        }
        #endregion

        #region AES加密，分组且不适用ECB方式 ,CBC
        public static string HighEncrypt(string password, string purpose, byte[] plainBytes)
        {
            byte[] key = AESUtils.PasswordToKey(password, purpose);
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    byte[] packedBytes = AESUtils.Pack(
                        version: 1,
                        iv: aes.IV,
                        cipherBytes: cipherBytes);
                    return Convert.ToBase64String(packedBytes);
                }
            }
        }

        public static byte[] HighDecrypt(string packedString, string password, string purpose)
        {
            byte[] key = AESUtils.PasswordToKey(password, purpose);
            byte[] packedBytes = Convert.FromBase64String(packedString);
            (byte version, byte[] iv, byte[] cipherBytes) = AESUtils.Unpack(packedBytes);
            using (var aes = Aes.Create())
            {
                using (ICryptoTransform decryptor = aes.CreateDecryptor(key, iv))
                {
                    return decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                }
            }
        }
        #endregion

        #region AES加密 安全等级居中
        /// <summary>
        /// AES加密算法  中等强度
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="strKey">密钥</param>
        /// <returns>返回加密后的密文字节数组</returns>
        public static byte[] NormalAESEncrypt(string plainText, string strKey)
        {
            //分组加密算法
            SymmetricAlgorithm des = Rijndael.Create();
            byte[] inputByteArray = Encoding.UTF8.GetBytes(plainText);//得到需要加密的字节数组
                                                                      //设置密钥及密钥向量
            des.Key = Encoding.UTF8.GetBytes(strKey);
            des.IV = _key1;
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            byte[] cipherBytes = ms.ToArray();//得到加密后的字节数组
            cs.Close();
            ms.Close();
            Console.WriteLine(Encoding.UTF8.GetString(cipherBytes));
            return cipherBytes;
        }

        /// <summary>
        /// AES解密  中等强度
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <param name="strKey">密钥</param>
        /// <returns>返回解密后的字符串</returns>
        public static byte[] NormalAESDecrypt(byte[] cipherText, string strKey)
        {
            SymmetricAlgorithm des = Rijndael.Create();
            des.Key = Encoding.UTF8.GetBytes(strKey);
            des.IV = _key1;
            byte[] decryptBytes = new byte[cipherText.Length];
            MemoryStream ms = new MemoryStream(cipherText);
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read);
            cs.Read(decryptBytes, 0, decryptBytes.Length);
            cs.Close();
            ms.Close();
            //return Convert.ToBase64String(decryptBytes);

            Console.WriteLine(Encoding.UTF8.GetString(decryptBytes));
            return decryptBytes;
        }
        #endregion
    }
}
