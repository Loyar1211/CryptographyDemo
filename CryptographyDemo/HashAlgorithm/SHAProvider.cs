using CryptographyDemo.Enums;
using CryptographyDemo.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyDemo.HashAlgorithm
{
    public class SHAProvider
    {
        /// <summary>
        /// 仅散列算法可以使用
        /// </summary>
        private static readonly string SaltKey1 = "AS2HD2NOA4SH34DTg87grfF9hb89Ht67GYG5jkbBABSD";//AS2HD2NOA4SH34DTg87grfF9hb89Ht67GYG5jkbBABSD
        private static readonly string SaltKey2 = "as23hdk344uhaASDu6a6i7o8s8ASDb8dniuaV1os23bd";//as23hdk344uhaASDu6a6i7o8s8ASDb8dniuaV1os23bd
        #region 散列算法
        /// <summary>
        /// SHA512
        /// </summary>
        /// <param name="pwd">密码</param>
        /// <returns></returns>
        public static string SHA512Create(string pwd)
        {
            Console.WriteLine(DateTime.Now);
            var polymerization = PublicTools.GeneralSlat(pwd, SaltKey1);

            SHA512 sha512 = SHA512.Create();
            polymerization = sha512.ComputeHash(polymerization);
            byte[] hash512Data = SHA512.HashData(polymerization);
            for (int i = 0; i < 1023; i++)
            {
                hash512Data = sha512.ComputeHash(hash512Data);
            }
            string result = PublicTools.ScatteredData(hash512Data, (int)Scattered.Half);
            Console.WriteLine(DateTime.Now);
            return result;
        }

        /// <summary>
        /// SHA256
        /// </summary>
        /// <param name="pwd"></param>
        /// <returns></returns>
        public static string SHA256Create(string pwd)
        {
            Console.WriteLine(DateTime.Now);
            var polymerization = PublicTools.GeneralSlat(pwd, SaltKey1);

            SHA256 sha256 = SHA256.Create();
            polymerization = sha256.ComputeHash(polymerization);
            byte[] hash256Data = SHA512.HashData(polymerization);
            for (int i = 0; i < 255; i++)
            {
                hash256Data = sha256.ComputeHash(hash256Data);
            }
            string result = PublicTools.ScatteredData(hash256Data, (int)Scattered.Half);
            Console.WriteLine(DateTime.Now);
            return result;
        }

        /// <summary>
        /// SHA384
        /// </summary>
        /// <param name="pwd"></param>
        /// <returns></returns>
        public static string SHA384Create(string pwd)
        {
            Console.WriteLine(DateTime.Now);
            var polymerization = PublicTools.GeneralSlat(pwd, SaltKey2);

            SHA384 sha384 = SHA384.Create();
            polymerization = sha384.ComputeHash(polymerization);
            byte[] hash384Data = SHA384.HashData(polymerization);
            for (int i = 0; i < 511; i++)
            {
                hash384Data = sha384.ComputeHash(hash384Data);
            }
            string result = PublicTools.ScatteredData(hash384Data, (int)Scattered.Half);
            Console.WriteLine(DateTime.Now);
            return result;
        }

        /// <summary>
        /// SHA-1
        /// </summary>
        /// <param name="pwd"></param>
        /// <returns></returns>
        public static string SHA1Create(string pwd)
        {
            Console.WriteLine(DateTime.Now);
            var source = PublicTools.GeneralSlat(pwd, SaltKey2);
            SHA1 sha1 = SHA1.Create();
            source = sha1.ComputeHash(source);
            byte[] hash384Data = SHA384.HashData(source);
            for (int i = 0; i < 511; i++)
            {
                hash384Data = sha1.ComputeHash(hash384Data);
            }
            string result = PublicTools.ScatteredData(hash384Data, (int)Scattered.Half);
            Console.WriteLine(DateTime.Now);
            return result;
        }
        #endregion
    }
}
