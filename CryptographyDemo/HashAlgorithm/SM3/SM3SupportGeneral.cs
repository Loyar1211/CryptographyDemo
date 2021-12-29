namespace CryptographyDemo.HashAlgorithm.SM3
{
    /// <summary>
    /// 可能存在不同的组合，所以覆盖多种参数不同过的应对方法
    /// </summary>
    public class SM3SupportGeneral
    {
        /// <summary>
        /// 使用特定字符执行无符号按位右移动
        /// </summary>
        /// <param name="number">要操作的编号</param>
        /// <param name="bits">要移动的位数</param>
        /// <returns></returns>
        public static int URShift(int number, long bits)
        {
            return URShift(number, (int)bits);
        }

        /// <summary>
        /// 使用特定数字进行无符号按位右移
        /// </summary>
        /// <param name="number">要操作的编号</param>
        /// <param name="bits">要移动的位数</param>
        /// <returns></returns>
        public static long URShift(long number, int bits)
        {
            if (number >= 0)
                return number >> bits;
            else
                return (number >> bits) + (2L << ~bits);
        }

        /// <summary>
        /// 使用特定数字进行无符号右位移
        /// </summary>
        /// <param name="number">要操作的编号</param>
        /// <param name="bits">要移动的位数</param>
        /// <returns></returns>
        public static int URShift(int number, int bits)
        {
            if (number >= 0)
                return number >> bits;
            else
                return (number >> bits) + (2 << ~bits);
        }

        /// <summary>
        /// 使用特定数字进行无符号按位右移
        /// </summary>
        /// <param name="num">要操作的编号</param>
        /// <param name="bits">要移动的位数</param>
        /// <returns></returns>
        public static long URShift(long num, long bits)
        {
            return URShift(num, (int)bits);
        }
    }
}
