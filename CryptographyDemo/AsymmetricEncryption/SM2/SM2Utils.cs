﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace CryptographyDemo.AsymmetricEncryption.SM2
{
    public class SM2Utils
    {
        public static void GenerateKeyPair()
        {
            SM2Provider sm2 = SM2Provider.Instance;
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;

            System.Console.Out.WriteLine("公钥: " + Encoding.Default.GetString(Hex.Encode(publicKey.GetEncoded())).ToUpper());
            System.Console.Out.WriteLine("私钥: " + Encoding.Default.GetString(Hex.Encode(privateKey.ToByteArray())).ToUpper());
        }

        public static String Encrypt(byte[] publicKey, byte[] data)
        {
            if (null == publicKey || publicKey.Length == 0)
            {
                return null;
            }
            if (data == null || data.Length == 0)
            {
                return null;
            }

            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            Cipher cipher = new Cipher();
            SM2Provider sm2 = SM2Provider.Instance;

            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            String sc1 = Encoding.Default.GetString(Hex.Encode(c1.GetEncoded()));
            String sc2 = Encoding.Default.GetString(Hex.Encode(source));
            String sc3 = Encoding.Default.GetString(Hex.Encode(c3));

            return (sc1 + sc2 + sc3).ToUpper();
        }

        public static byte[] Decrypt(byte[] privateKey, byte[] encryptedData)
        {
            if (null == privateKey || privateKey.Length == 0)
            {
                return null;
            }
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return null;
            }

            String data = Encoding.Default.GetString(Hex.Encode(encryptedData));

            byte[] c1Bytes = Hex.Decode(Encoding.Default.GetBytes(data.Substring(0, 130)));
            int c2Len = encryptedData.Length - 97;
            byte[] c2 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130, 2 * c2Len)));
            byte[] c3 = Hex.Decode(Encoding.Default.GetBytes(data.Substring(130 + 2 * c2Len, 64)));

            SM2Provider sm2 = SM2Provider.Instance;
            BigInteger userD = new BigInteger(1, privateKey);

            ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }
    }
}
