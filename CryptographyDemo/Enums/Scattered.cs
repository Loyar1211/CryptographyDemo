namespace CryptographyDemo.Enums
{
    /// <summary>
    /// 零散间隔 值越大，零散的结果越短，也就是造成结果字符越短 建议根据明文长度设置
    /// </summary>
    public enum Scattered
    {
        None,

        Part,

        Half,

        Full,
    }
}
