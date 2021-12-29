using CryptographyDemo.Enums;
using CryptographyDemo;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CryptographyDemo.AsymmetricEncryption;
using CryptographyDemo.HashAlgorithm;
using CryptographyDemo.SymmetricEncryption;
using CryptographyDemo.HashAlgorithm.SM3;
using CryptographyDemo.SymmetricEncryption.AES;
using CryptographyDemo.SymmetricEncryption.SM4;
/// <summary>
/// 此处引用请勿修改
/// </summary>

namespace CryptographyDemo
{
    /// <summary>
    /// 该Demo包含目前加密方式有{国密（SM2\3\4）AES,DES,RSA,SHA,XOR,散列哈希,以及部分ECC的计算}
    /// 目前缺少的加密方式 SM1（不太可能）,ECC（需要掌握解离散数学难题）,IDEA（经典历史加密方式）,3DES（升级密钥计算的DES），
    /// <CreateBy>赵帅州</CreateBy>
    /// <CreateOn>20211229</CreateOn>
    /// <Telephone_and_Wechat_number>18600340530</Telephone_and_Wechat_number>
    /// <Email>18600340530@139.com</Email>
    /// </summary>
    public class Program
    {
        #region RSA密钥
        //2048 公钥
        private static string publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoQh0wEqx/R2H1v00IU12Oc30fosRC/frhH89L6G+fzeaqI19MYQhEPMU13wpeqRONCUta+2iC1sgCNQ9qGGf19yGdZUfueaB1Nu9rdueQKXgVurGHJ+5N71UFm+OP1XcnFUCK4wT5d7ZIifXxuqLehP9Ts6sNjhVfa+yU+VjF5HoIe69OJEPo7OxRZcRTe17khc93Ic+PfyqswQJJlY/bgpcLJQnM+QuHmxNtF7/FpAx9YEQsShsGpVo7JaKgLo+s6AFoJ4QldQKir2vbN9vcKRbG3piElPilWDpjXQkOJZhUloh/jd7QrKFimZFldJ1r6Q59QYUyGKZARUe0KZpMQIDAQAB";
        //2048 私钥
        private static string privateKey = "MIIEpAIBAAKCAQEAoQh0wEqx/R2H1v00IU12Oc30fosRC/frhH89L6G+fzeaqI19MYQhEPMU13wpeqRONCUta+2iC1sgCNQ9qGGf19yGdZUfueaB1Nu9rdueQKXgVurGHJ+5N71UFm+OP1XcnFUCK4wT5d7ZIifXxuqLehP9Ts6sNjhVfa+yU+VjF5HoIe69OJEPo7OxRZcRTe17khc93Ic+PfyqswQJJlY/bgpcLJQnM+QuHmxNtF7/FpAx9YEQsShsGpVo7JaKgLo+s6AFoJ4QldQKir2vbN9vcKRbG3piElPilWDpjXQkOJZhUloh/jd7QrKFimZFldJ1r6Q59QYUyGKZARUe0KZpMQIDAQABAoIBAQCRZLUlOUvjIVqYvhznRK1OG6p45s8JY1r+UnPIId2Bt46oSLeUkZvZVeCnfq9k0Bzb8AVGwVPhtPEDh73z3dEYcT/lwjLXAkyPB6gG5ZfI/vvC/k7JYV01+neFmktw2/FIJWjEMMF2dvLNZ/Pm4bX1Dz9SfD/45Hwr8wqrvRzvFZsj5qqOxv9RPAudOYwCwZskKp/GF+L+3Ycod1Wu98imzMZUH+L5dQuDGg3kvf3ljIAegTPoqYBg0imNPYY/EGoFKnbxlK5S5/5uAFb16dGJqAz3XQCz9Is/IWrOTu0etteqV2Ncs8uqPdjed+b0j8CMsr4U1xjwPQ8WwdaJtTkRAoGBANAndgiGZkCVcc9975/AYdgFp35W6D+hGQAZlL6DmnucUFdXbWa/x2rTSEXlkvgk9X/PxOptUYsLJkzysTgfDywZwuIXLm9B3oNmv3bVgPXsgDsvDfaHYCgz0nHK6NSrX2AeX3yO/dFuoZsuk+J+UyRigMqYj0wjmxUlqj183hinAoGBAMYMOBgF77OXRII7GAuEut/nBeh2sBrgyzR7FmJMs5kvRh6Ck8wp3ysgMvX4lxh1ep8iCw1R2cguqNATr1klOdsCTOE9RrhuvOp3JrYzuIAK6MpH/uBICy4w1rW2+gQySsHcH40r+tNaTFQ7dQ1tef//iy/IW8v8i0t+csztE1JnAoGABdtWYt8FOYP688+jUmdjWWSvVcq0NjYeMfaGTOX/DsNTL2HyXhW/Uq4nNnBDNmAz2CjMbZwt0y+5ICkj+2REVQVUinAEinTcAe5+LKXNPx4sbX3hcrJUbk0m+rSu4G0B/f5cyXBsi9wFCAzDdHgBduCepxSr04Sc9Hde1uQQi7kCgYB0U20HP0Vh+TG2RLuE2HtjVDD2L/CUeQEiXEHzjxXWnhvTg+MIAnggvpLwQwmMxkQ2ACr5sd/3YuCpB0bxV5o594nsqq9FWVYBaecFEjAGlWHSnqMoXWijwu/6X/VOTbP3VjH6G6ECT4GR4DKKpokIQrMgZ9DzaezvdOA9WesFdQKBgQCWfeOQTitRJ0NZACFUn3Fs3Rvgc9eN9YSWj4RtqkmGPMPvguWo+SKhlk3IbYjrRBc5WVOdoX8JXb2/+nAGhPCuUZckWVmZe5pMSr4EkNQdYeY8kOXGSjoTOUH34ZdKeS+e399BkBWIiXUejX/Srln0H4KoHnTWgxwNpTsBCgXu8Q==";
        #endregion
         
        #region DES密钥
        /// <summary>
        /// 可以根据加密逻辑进行变更，目前是八位
        /// </summary>
        private static string DESKey = "DesTest1";
        #endregion

        #region SM3密钥
        private static string SM3Keys = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoQh0wEqx/R2H1v00IU12Oc30fosRC/frhH89L6G+fzeaqI19MYQhEPMU13wpeqRONCUta+2iC1sgCNQ9qGGf19yGdZUfueaB1Nu9rdueQKXgVurGHJ+5N71UFm+OP1XcnFUCK4wT5d7ZIifXxuqLehP9Ts6sNjhVfa+yU+VjF5HoIe69OJEPo7OxRZcRTe17khc93Ic+PfyqswQJJlY/bgpcLJQnM+QuHmxNtF7/FpAx9YEQsShsGpVo7JaKgLo+s6AFoJ4QldQKir2vbN9vcKRbG3piElPilWDpjXQkOJZhUloh/jd7QrKFimZFldJ1r6Q59QYUyGKZARUe0KZpMQIDAQAB";
        #endregion

        #region AES密钥
        private static string AESKeys = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoQh0wEqx/R2H1v00IU12Oc30fosRC/frhH89L6G+fzeaqI19MYQhEPMU13wpeqRONCUta+2iC1sgCNQ9qGGf19yGdZUfueaB1Nu9rdueQKXgVurGHJ+5N71UFm+OP1XcnFUCK4wT5d7ZIifXxuqLehP9Ts6sNjhVfa+yU+VjF5HoIe69OJEPo7OxRZcRTe17khc93Ic+PfyqswQJJlY/bgpcLJQnM+QuHmxNtF7/FpAx9YEQsShsGpVo7JaKgLo+s6AFoJ4QldQKir2vbN9vcKRbG3piElPilWDpjXQkOJZhUloh/jd7QrKFimZFldJ1r6Q59QYUyGKZARUe0KZpMQIDAQAB";
        #endregion

        static void Main(string[] args)
        {
            #region 散列算法(不考虑MD5)
            ///////////////////////////////////////

            #region 测试 SHA算法结果
            //string SHApwd = "12345";
            //Console.WriteLine("Password：" + SHApwd);
            //Console.WriteLine("");
            //Console.WriteLine("SHA256：" + SHAProvider.SHA256Create(SHApwd));
            //Console.WriteLine("Twice=>SHA256：" + SHAProvider.SHA256Create(SHApwd));
            //Console.WriteLine("");
            //Console.WriteLine("SHA384：" + SHAProvider.SHA384Create(SHApwd));
            //Console.WriteLine("Twice=>SHA384：" + SHAProvider.SHA384Create(SHApwd));
            //Console.WriteLine("");
            //Console.WriteLine("SHA512：" + SHAProvider.SHA512Create(SHApwd));
            //Console.WriteLine("Twice=>SHA512：" + SHAProvider.SHA512Create(SHApwd));
            //Console.WriteLine("");
            //Console.WriteLine("SHA1  ：" + SHAProvider.SHA1Create(SHApwd));
            //Console.WriteLine("Twice=>SHA1：" + SHAProvider.SHA1Create(SHApwd));
            //Console.WriteLine("");
            #endregion

            #region 测试 国密SM3算法结果      
            //var SM3Pwd = "123456789";//密码
            //Console.WriteLine(DateTime.Now);
            //Console.WriteLine("Init Pwd:" + SM3Pwd);
            //Console.WriteLine("");

            //Console.WriteLine("SM3 and Keys result:" + SM3Crypto.ToSM3byte(SM3Pwd, SM3Keys));
            //Console.WriteLine("");

            //Console.WriteLine("SM3 default hash result:" + SM3Pwd.ToSM3byte());
            //Console.WriteLine("");
            //Console.WriteLine(DateTime.Now);
            #endregion

            ///////////////////////////////////////
            #endregion

            #region 非对称加密
            ///////////////////////////////////////

            #region 测试 RSA结果 
            //var rsaHelper = new RSAProvider(RSAType.RSA2, Encoding.UTF8, privateKey, publicKey);

            /////假设密码
            //string RSAPwd = "Zhao19961211*&^%.";
            //Console.WriteLine("Init PWD:" + RSAPwd);
            //Console.WriteLine("");

            ////加密
            //string enStr = rsaHelper.Encrypt(RSAPwd);
            //Console.WriteLine("Encryp result:" + enStr);
            //Console.WriteLine("");

            ////解密
            //string deStr = rsaHelper.Decrypt(enStr);
            //Console.WriteLine("Decrypt result:" + deStr);
            //Console.WriteLine("");

            ////私钥签名
            //string signStr = rsaHelper.Sign(RSAPwd);
            //Console.WriteLine("String sign:" + signStr);
            //Console.WriteLine("");

            ////公钥签名进行验证
            //bool signVerify = rsaHelper.Verify(RSAPwd, signStr);
            //Console.WriteLine("");
            //Console.WriteLine("Verify result:" + signVerify);
            #endregion

            ///////////////////////////////////////
            #endregion

            #region 对称加密
            ///////////////////////////////////////

            #region 测试 DES结果
            //DESProvider desProvider = new DESProvider(Encoding.UTF8);
            //string DESPwd = "123456789";

            /////加密结果输出
            //var encryptResult = desProvider.CreateDESEncrypt(DESPwd, DESKey);
            //Console.WriteLine("DES_EncryptResult:" + encryptResult);
            //Console.WriteLine("");

            /////解密结果显示明文
            //var decryptResult = desProvider.CreateDESDecrypt(encryptResult, DESKey);
            //Console.WriteLine("DES_DecryptResult:" + decryptResult);
            //Console.WriteLine("");
            #endregion

            #region 测试 AES CBC结果  高等级
            //string AESPwd = "123456789";
            //string purpose = "这个测试就是是用来做SS0";
            //Console.WriteLine(DateTime.Now);
            //Console.WriteLine("init pwd:" + AESPwd);
            //Console.WriteLine("");

            //string AESHighEncryptResult = AESProvider.HighEncrypt(AESPwd, purpose, Encoding.UTF8.GetBytes("Hello World"));
            //Console.WriteLine("Encrypt pwd:" + AESHighEncryptResult);
            //Console.WriteLine("");

            //Console.WriteLine("Decrypt pwd:" + AESProvider.HighDecrypt(AESHighEncryptResult, AESPwd, purpose));
            //Console.WriteLine("");
            //Console.WriteLine(DateTime.Now);
            #endregion

            #region 测试 AES 中等强度结果 TL OR
            //string AESNormalPwd = "123456789";
            //Console.WriteLine(DateTime.Now);
            //Console.WriteLine("init pwd:" + AESNormalPwd);
            //Console.WriteLine("");

            //var NormalEncryptResult = AESProvider.NormalAESEncrypt(AESNormalPwd, "1111111111111111");
            //Console.WriteLine("Encrypt pwd:" + string.Join(string.Empty, NormalEncryptResult));
            //Console.WriteLine("");

            //Console.WriteLine("Decrypt pwd:" + string.Join(string.Empty, AESProvider.NormalAESDecrypt(NormalEncryptResult, "1111111111111111")));
            //Console.WriteLine("");
            //Console.WriteLine(DateTime.Now);
            #endregion

            #region 测试 异或结果
            //XORProvider.CreateXOR();
            #endregion

            #region 测试 SM4结果 极复杂序列计算
            //String SM4Pwd = "ererfeiisgod";

            //SM4Utils sm4 = new SM4Utils();
            //sm4.secretKey = "JeF8U9wHFOMfs2Y8";
            //sm4.hexString = false;

            //System.Console.Out.WriteLine("ECB model");
            //String cipherText = sm4.Encrypt_ECB(SM4Pwd);
            //System.Console.Out.WriteLine("Encrypt result: " + cipherText);
            //System.Console.Out.WriteLine("");

            //SM4Pwd = sm4.Decrypt_ECB(cipherText);
            //System.Console.Out.WriteLine("Decrypt result: " + SM4Pwd);
            //System.Console.Out.WriteLine("");

            //System.Console.Out.WriteLine("CBC model");
            //sm4.iv = "UISwD9fW6cFh9SNS";
            //cipherText = sm4.Encrypt_CBC(SM4Pwd);
            //System.Console.Out.WriteLine("Encrypt result: " + cipherText);
            //System.Console.Out.WriteLine("");

            //SM4Pwd = sm4.Decrypt_CBC(cipherText);
            //System.Console.Out.WriteLine("Decrypt result: " + SM4Pwd);
            #endregion

            ///////////////////////////////////////
            #endregion

            Console.ReadKey();
        }
    }
}
