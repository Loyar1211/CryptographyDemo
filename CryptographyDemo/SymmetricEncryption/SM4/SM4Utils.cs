using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace CryptographyDemo.SymmetricEncryption.SM4
{
    public class SM4Utils
    {
        public string secretKey = "";
        public string iv = "";
        public bool hexString = false;

        public string Encrypt_ECB(string plainText)
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4Provider.SM4_ENCRYPT;

            byte[] keyBytes;
            if (hexString)
            {
                keyBytes = Hex.Decode(secretKey);
            }
            else
            {
                keyBytes = Encoding.Default.GetBytes(secretKey);
            }

            SM4Provider sm4 = new SM4Provider();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, Encoding.Default.GetBytes(plainText));

            string cipherText = Encoding.Default.GetString(Hex.Encode(encrypted));
            return cipherText;
        }

        public string Decrypt_ECB(string cipherText)
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4Provider.SM4_DECRYPT;

            byte[] keyBytes;
            if (hexString)
            {
                keyBytes = Hex.Decode(secretKey);
            }
            else
            {
                keyBytes = Encoding.Default.GetBytes(secretKey);
            }

            SM4Provider sm4 = new SM4Provider();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Hex.Decode(cipherText));
            return Encoding.Default.GetString(decrypted);
        }
        public string Encrypt_CBC(string plainText)
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4Provider.SM4_ENCRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (hexString)
            {
                keyBytes = Hex.Decode(secretKey);
                ivBytes = Hex.Decode(iv);
            }
            else
            {
                keyBytes = Encoding.Default.GetBytes(secretKey);
                ivBytes = Encoding.Default.GetBytes(iv);
            }

            SM4Provider sm4 = new SM4Provider();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Encoding.Default.GetBytes(plainText));

            string cipherText = Encoding.Default.GetString(Hex.Encode(encrypted));
            return cipherText;
        }

        public string Decrypt_CBC(string cipherText)
        {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4Provider.SM4_DECRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (hexString)
            {
                keyBytes = Hex.Decode(secretKey);
                ivBytes = Hex.Decode(iv);
            }
            else
            {
                keyBytes = Encoding.Default.GetBytes(secretKey);
                ivBytes = Encoding.Default.GetBytes(iv);
            }

            SM4Provider sm4 = new SM4Provider();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Hex.Decode(cipherText));
            return Encoding.Default.GetString(decrypted);
        }
    }
}
