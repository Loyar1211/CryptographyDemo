using CryptographyDemo.Enums;
using Org.BouncyCastle.Crypto;
using System;

namespace CryptographyDemo.HashAlgorithm.SM3
{
    public abstract class SM3GeneralDigest : IDigest
    {
        /// <summary>
        /// 无参构造函数
        /// </summary>
        internal SM3GeneralDigest()
        {
            SBuf = new byte[4];
        }

        /// <summary>
        /// 定义内部缓存区大小
        /// </summary>
        private const int ByteLength = 64;

        /// <summary>
        /// 内部消息摘要
        /// </summary>
        private readonly byte[] SBuf;

        /// <summary>
        /// 待更新的内部消息摘要索引
        /// </summary>
        private int SBufoff;

        /// <summary>
        /// 待更新的内部消息摘要索引大小
        /// </summary>
        private int SBufoffCount;

        /// <summary>
        /// 算法名称
        /// </summary>
        public abstract string AlgorithmName { get; }

        /// <summary>
        /// 有参构造函数
        /// </summary>
        /// <param name="noop"></param>
        internal SM3GeneralDigest(SM3GeneralDigest noop)
        {
            SBuf = new byte[noop.SBuf.Length];
            Buffer.BlockCopy(noop.SBuf, 0, SBuf, 0, noop.SBuf.Length);

            SBufoff = noop.SBufoff;
            SBufoffCount = noop.SBufoffCount;
        }

        /// <summary>
        /// 处理消息摘要
        /// ABCDEFGH 串联
        /// </summary>
        /// <param name="input"></param>
        /// <param name="inOff"></param>
        internal abstract void ProcessWord(byte[] input, int inOff);
        internal abstract void ProcessLength(long bitlength);

        /// <summary>
        /// 迭代压缩
        /// </summary>
        internal abstract void ProcessBlock();

        /// <summary>
        /// 字节快更新整个消息摘要
        /// </summary>
        /// <param name="input">输入</param>
        /// <param name="inOff">z坐标</param>
        /// <param name="length">长度</param>
        /// <exception cref="NotImplementedException"></exception>
        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            //更新当前的消息摘要
            while ((SBufoff != 0) && (length > 0))
            {
                Update(input[inOff]);
                inOff++;
                length--;
            }

            //处理完整的消息摘要
            while (length > SBuf.Length)
            {
                ProcessWord(input, inOff);

                inOff += SBuf.Length;
                length -= SBuf.Length;
                SBufoffCount += SBuf.Length;
            }

            //填充剩余的消息摘要
            while (length > 0)
            {
                Update(input[inOff]);
                inOff++;
                length--;
            }
        }

        /// <summary>
        /// 关闭摘要，产生最终的摘要值，dofinal调用使得摘要复位
        /// </summary>
        /// <param name="output"></param>
        /// <param name="outOff"></param>
        /// <returns></returns>
        public abstract int DoFinal(byte[] output, int outOff);

        /// <summary>
        /// 摘要应用其压缩功能的内部缓冲区的大小
        /// </summary>
        /// <returns></returns>
        public int GetByteLength() => ByteLength;

        /// <summary>
        /// 消息摘要生成的摘要的大小
        /// </summary>
        /// <returns></returns>
        public abstract int GetDigestSize();

        /// <summary>
        /// 重启
        /// </summary>
        public virtual void Reset()
        {
            SBufoffCount = 0;
            SBufoff = 0;
            Array.Clear(SBuf, (int)Scattered.None, SBuf.Length);
        }

        /// <summary>
        /// 完成消息摘要,产生最终的结果值
        /// </summary>
        public void Finish()
        {
            long bitLength = SBufoffCount << (int)Scattered.Full;

            //添加字节占位
            Update(unchecked(128));

            while (SBufoff != 0x0) Update(unchecked((int)Scattered.None));
            ProcessLength(bitLength);
            ProcessBlock();
        }

        /// <summary>
        /// 字节更新摘要
        /// </summary>
        /// <param name="input">输入字节</param>
        /// <exception cref="NotImplementedException"></exception>
        public void Update(byte input)
        {
            SBuf[SBufoff++] = input;

            if (SBufoff == SBuf.Length)
            {
                ProcessWord(SBuf, (int)Scattered.None);
                SBufoff = (int)Scattered.None;
            }
            SBufoffCount = (int)Scattered.None;
        }
    }
}
