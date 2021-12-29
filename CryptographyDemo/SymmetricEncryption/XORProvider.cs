using System;

namespace CryptographyDemo.SymmetricEncryption
{
    public static class XORProvider
    {
        /// <summary>
        /// 最简单的异或加密方式
        /// </summary>
        public static void CreateXOR()
        {
            string pwd = "123456789";//原始数据
            Console.WriteLine("Init pwd:" + pwd);
            string temp = "";//中间变量
            char tempChar = '\0';
            for (int i = 0; i < pwd.Length; i++)//加密
            {
                tempChar = Convert.ToChar(pwd[i] ^ '1');
                temp += tempChar;
            }
            Console.WriteLine("Encrypt result:" + temp);
            temp = "";
            for (int i = 0; i < temp.Length; i++)//解密
            {
                tempChar = Convert.ToChar(temp[i] ^ '1');
                pwd += tempChar;
            }
            Console.WriteLine("Decrypt result:" + pwd);
        }
    }
}
