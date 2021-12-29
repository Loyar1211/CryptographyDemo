using CryptographyDemo.Enums;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.AsymmetricEncryption
{
    public class RSAProvider
    {
        /// <summary>
        /// 私钥容器
        /// </summary>
        private readonly RSA _privateKeyRsaProvider;

        /// <summary>
        /// 公钥容器
        /// </summary>
        private readonly RSA _publicKeyRsaProvider;

        /// <summary>
        /// 加密签名
        /// </summary>
        private readonly HashAlgorithmName _hashAlgorithmName;

        /// <summary>
        /// 编码类型
        /// </summary>
        private readonly Encoding _encoding;

        /// <summary>
        /// 调用RSA 构造函数
        /// </summary>
        /// <param name="rsaType">加密类型，RSA SHA1 SHA2  RSA2  SHA256 密钥长度至少为2048</param>
        /// <param name="encoding">编码类型</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="publicKey">公钥</param>
        public RSAProvider(RSAType rsaType, Encoding encoding, string privateKey, string publicKey = null)
        {
            this._encoding = encoding;
            if (!string.IsNullOrEmpty(privateKey))
            {
                _privateKeyRsaProvider = CreateRsaProviderFromPrivateKey(privateKey);
            }
            if (!string.IsNullOrEmpty(publicKey))
            {
                _publicKeyRsaProvider = CreateRsaProviderFromPublicKey(publicKey);
            }
            _hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
        }

        #region  签名
        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string Sign(string data)
        {
            byte[] dataBytes = _encoding.GetBytes(data);
            var signatureBytes = _privateKeyRsaProvider.SignData(dataBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }

        /// <summary>
        /// 公钥验证签名
        /// </summary>
        /// <param name="data">原始明文</param>
        /// <param name="sign">签名结果</param>
        /// <returns></returns>
        public bool Verify(string data, string sign)
        {
            byte[] dataBytes = _encoding.GetBytes(data);
            byte[] signBytes = Convert.FromBase64String(sign);
            var verifyResult = _publicKeyRsaProvider.VerifyData(dataBytes, signBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return verifyResult;
        }
        #endregion

        #region 解密  加密
        /// <summary>
        /// 根据私钥容器进行解密 
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Decrypt(string cipherText)
        {
            if (_privateKeyRsaProvider == null)
            {
                throw new Exception("私钥容器不能为空，故不能解密");
            }
            return Encoding.UTF8.GetString(_privateKeyRsaProvider.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.Pkcs1));
        }

        public string Encrypt(string text)
        {
            if (_publicKeyRsaProvider == null)
            {
                throw new Exception("公钥容器不能为空，故不能加密");
            }
            return Convert.ToBase64String(_publicKeyRsaProvider.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.Pkcs1));
        }
        #endregion

        #region 使用公钥、私钥创建RSA实例
        /// <summary>
        /// 使用私钥创建RSA实例
        /// </summary>
        /// <returns></returns>
        public RSA CreateRsaProviderFromPrivateKey(string privateKey)
        {
            byte[] privateKeyBits = Convert.FromBase64String(privateKey);

            var rsa = RSA.Create();//创建实例
            var rsaParameters = new RSAParameters();

            using (BinaryReader binary = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twoBytes = 0;
                twoBytes = binary.ReadUInt16();//33328

                if (twoBytes == 0x8130)
                    binary.ReadByte();
                else if (twoBytes == 0x8230)
                    binary.ReadUInt16();
                else
                    throw new Exception("私钥读取发生错误");

                twoBytes = binary.ReadUInt16();

                if (twoBytes != 0x0102)
                    throw new Exception("私钥值不符合ReadUInt16()规范");

                bt = binary.ReadByte();

                if (bt != 0x00)
                    throw new Exception("私钥值不符合ReadByte()规范");

                ///设置RSA算法中的集参数
                ///系统Exponent参数   该处有优先顺序，逐渐向下读取字节
                rsaParameters.Modulus = binary.ReadBytes(GetIntergerSize(binary));
                ///系统Exponent参数
                rsaParameters.Exponent = binary.ReadBytes(GetIntergerSize(binary));
                ///系统D参数
                rsaParameters.D = binary.ReadBytes(GetIntergerSize(binary));
                ///系统P参数
                rsaParameters.P = binary.ReadBytes(GetIntergerSize(binary));
                ///系统Q参数
                rsaParameters.Q = binary.ReadBytes(GetIntergerSize(binary));
                ///系统DP参数
                rsaParameters.DP = binary.ReadBytes(GetIntergerSize(binary));
                ///系统DQ参数
                rsaParameters.DQ = binary.ReadBytes(GetIntergerSize(binary));
                ///系统InverseQ参数
                rsaParameters.InverseQ = binary.ReadBytes(GetIntergerSize(binary));
            }
            rsa.ImportParameters(rsaParameters);//注入计算后的结果
            return rsa;
        }

        /// <summary>
        /// 使用公钥创建RSA实例
        /// </summary>
        /// <param name="publicKeyString"></param>
        /// <returns></returns>
        public RSA CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            // OID编码序列为 PKCS.1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            var x509Key = Convert.FromBase64String(publicKeyString);

            ///设置流读取ASN.1编码的SubjectPublicKeyInfo blob
            using (MemoryStream mem = new MemoryStream(x509Key))
            {
                //使用BinaryReader对字节流进行读取  可升级为Buffer
                using (BinaryReader binr = new BinaryReader(mem))
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //由小到大读取 30>81
                        binr.ReadByte();//向前读取一字节
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();//向前读取两个字节
                    else
                        return null;

                    seq = binr.ReadBytes(15);//读取序列号
                    if (!CompanyByteArrays(seq, seqOid))//检查OID并验证顺序是否正确
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103) //由小到大读取 03>81
                        binr.ReadByte();//向前读取一字节
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();//向前读取两个字节
                    else
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x00)//处理为空的字节
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130)//由小到大读取 30>81
                        binr.ReadByte();//向前读取一字节
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();//向前读取两个字节
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102)//由小到大读取 30>81
                        lowbyte = binr.ReadByte();//读取下一个字节，并以modules数表示
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte();//下两个字节
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };//反序处理 1使用由大开始
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {   //如果modules第一个字节，最高阶为0 则不进行处理
                        binr.ReadByte();//保证是null
                        modsize -= 1;//将缓存区快的大小-1，丢掉null byte
                    }

                    byte[] modulus = binr.ReadBytes(modsize);//读取modules数

                    if (binr.ReadByte() != 0x02)//指数数据应该为整数 排除
                        return null;
                    int expbytes = (int)binr.ReadByte();//在所有可用值中，指数数据只需要一个字节占位
                    byte[] exponent = binr.ReadBytes(expbytes);

                    //使用公钥创建RSA实例容器
                    var rsa = RSA.Create();
                    RSAParameters rsaKeyInfo = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    rsa.ImportParameters(rsaKeyInfo);

                    return rsa;
                }
            }
        }
        #endregion

        #region 密钥算法
        /// <summary>
        /// 根据int32进行计算和读取
        /// </summary>
        /// <param name="binary"></param>
        /// <returns></returns>
        private int GetIntergerSize(BinaryReader binary)
        {
            byte bt = 0;
            int count = 0;
            bt = binary.ReadByte();

            if (bt != 0x02)
                return 0;//无数据

            bt = binary.ReadByte();

            if (bt == 0x81)
                count = binary.ReadByte();
            else
                if (bt == 0x82)
            {
                var highByte = binary.ReadByte();
                var lowByte = binary.ReadByte();
                byte[] modint = { lowByte, highByte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }

            while (binary.ReadByte() == 0x00)//计算到0截至
                count -= 1;

            binary.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        /// <summary>
        /// 对两个字节数组进行对比
        /// </summary>
        /// <param name="firstByte">第一个字节数组</param>
        /// <param name="secondByte">第二个字节数组</param>
        /// <returns></returns>
        private bool CompanyByteArrays(byte[] firstByte, byte[] secondByte)
        {
            if (Buffer.ByteLength(firstByte) != Buffer.ByteLength(secondByte))
                return false;

            int i = 0;

            foreach (var item in firstByte)
            {
                if (item != secondByte[i])
                    return false;

                i++;
            }

            return true;
        }
        #endregion
    }
}
