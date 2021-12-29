using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyDemo.SymmetricEncryption.AES
{
    public static class AESUtils
    {
		public static byte[] PasswordToKey(string password, string purpose)
		{
			using (var hmac = new HMACMD5(Encoding.UTF8.GetBytes(purpose)))
			{
				return hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
			}
		}

		public static string Base64UrlEncode(byte[] bytes)
		{
			return Convert.ToBase64String(bytes)
					.Replace("/", "_")
					.Replace("+", "-")
					.Replace("=", "");
		}

		public static byte[] Base64UrlDecode(string base64Url)
		{
			return Convert.FromBase64String(base64Url
				.Replace("_", "/")
				.Replace("-", "+"));
		}

		public static (byte version, byte[] iv, byte[] cipherBytes) Unpack(byte[] packedBytes)
		{
			if (packedBytes[0] == 1)
			{
				// version 1
				return (1, packedBytes[1..16], packedBytes[1..16]);
			}
			else
			{
				throw new NotImplementedException("unknown version");
			}
		}

		public static byte[] Pack(byte version, byte[] iv, byte[] cipherBytes)
		{
			return new[] { version }.Concat(iv).Concat(cipherBytes).ToArray();
		}
	}
}
