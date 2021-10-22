using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ProSoft.Crypto.Hash
{
    public static class HashMethods
    {
        private static string ByteToString(byte[] buff)
        {
            string binaryString = "";

            for (int i = 0; i < buff.Length; i++)
                binaryString += buff[i].ToString("X2"); // hex format

            return (binaryString);
        }

        public static class Hmac
        {
            public enum HmacType
            {
                Md5,
                HmacSha1,
                HmacSha256,
                HmacSha384,
                HmacSha512
            }

            public static string CreateHmac(string message, string secretKey, HmacType type)
            {
                secretKey = secretKey ?? String.Empty;
                var encoding = new ASCIIEncoding();
                byte[] keyByte = encoding.GetBytes(secretKey);
                byte[] messageBytes = encoding.GetBytes(message);

                switch (type)
                {
                    case HmacType.Md5:
                        using (var md5 = new HMACMD5(keyByte))
                        {
                            byte[] hashmessage = md5.ComputeHash(messageBytes);
                            return ByteToString(hashmessage);
                        }

                    case HmacType.HmacSha1:
                        using (var sha1 = new HMACSHA1(keyByte))
                        {
                            byte[] hashmessage = sha1.ComputeHash(messageBytes);
                            return ByteToString(hashmessage).ToLower();
                        }

                    case HmacType.HmacSha256:
                        using (var sha256 = new HMACSHA256(keyByte))
                        {
                            byte[] hashmessage = sha256.ComputeHash(messageBytes);
                            return ByteToString(hashmessage).ToLower();
                        }

                    case HmacType.HmacSha384:
                        using (var sha384 = new HMACSHA384(keyByte))
                        {
                            byte[] hashmessage = sha384.ComputeHash(messageBytes);
                            return ByteToString(hashmessage).ToLower();
                        }

                    case HmacType.HmacSha512:
                        using (var sha512 = new HMACSHA512(keyByte))
                        {
                            byte[] hashmessage = sha512.ComputeHash(messageBytes);
                            return ByteToString(hashmessage).ToLower();
                        }
                    default:
                        return null;
                }
            }
        }

        public enum HashType : int
        {
            Md5,
            Sha1,
            Sha256,
            Sha512,
            Unknown
        }

        public static string GetHashForString(string inputString, HashType hashType)
        {
            byte[] testStringAsBytes = Encoding.Default.GetBytes(inputString.Replace("-", string.Empty).Replace(" ", string.Empty));

            switch (hashType)
            {
                case HashType.Sha1:
                    var sha1 = new SHA1Managed();
                    byte[] sha1Checksum = sha1.ComputeHash(testStringAsBytes);
                    return ByteToString(sha1Checksum).Replace("-", string.Empty).Replace(" ", string.Empty).ToLower();

                case HashType.Sha256:
                    var sha256 = new SHA256Managed();
                    byte[] sha256Checksum = sha256.ComputeHash(testStringAsBytes);
                    return ByteToString(sha256Checksum).Replace("-", string.Empty).Replace(" ", string.Empty).ToLower();

                case HashType.Sha512:
                    var sha512 = new SHA512Managed();
                    byte[] sha512Checksum = sha512.ComputeHash(testStringAsBytes);
                    return ByteToString(sha512Checksum).Replace("-", string.Empty).Replace(" ", string.Empty).ToLower();

                default:
                    return "UNSUPPORTED_HASH_TYPE_FOR_FUNCTION";
            }
        }

        public static string GetHashForFile(string filename, HashType hashType)
        {
            using (FileStream stream = File.OpenRead(filename))
            {
                switch (hashType)
                {
                    case HashType.Md5:
                        using (var md5 = MD5.Create())
                            return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty).Replace(" ", string.Empty).ToLower();

                    case HashType.Sha1:
                        var sha1 = new SHA1Managed();
                        byte[] sha1Checksum = sha1.ComputeHash(stream);
                        return BitConverter.ToString(sha1Checksum).Replace("-", string.Empty).Replace(" ", string.Empty).ToLower();

                    case HashType.Sha256:
                        var sha256 = new SHA256Managed();
                        byte[] sha256Checksum = sha256.ComputeHash(stream);
                        return BitConverter.ToString(sha256Checksum).Replace("-", string.Empty).Replace(" ", string.Empty).ToLower();

                    case HashType.Sha512:
                        var sha512 = new SHA512Managed();
                        byte[] sha512Checksum = sha512.ComputeHash(stream);
                        return BitConverter.ToString(sha512Checksum).Replace("-", string.Empty).Replace(" ", string.Empty).ToLower();

                    default:
                        return string.Empty;
                }
            }
        }

        public static class Utils
        {
            public static HashType GetHashTypeFromHashLength(string hash)
            {
                var returnType = HashType.Unknown;

                if (!string.IsNullOrEmpty(hash))
                {
                    if (hash.Length == 32) returnType = HashType.Md5;
                    if (hash.Length == 40) returnType = HashType.Sha1;
                    if (hash.Length == 64) returnType = HashType.Sha256;
                    if (hash.Length == 128) returnType = HashType.Sha512;
                }

                return returnType;
            }

            public static bool CheckHash(string original, string hashString, HashType hashType)
            {
                string originalHash = GetHashForString(original, hashType);
                return (originalHash == hashString);
            }

            public static string GetHashNameFromHashType(HashType hash)
            {
                if (hash == HashType.Md5) return "MD5";
                if (hash == HashType.Sha1) return "SHA1";
                if (hash == HashType.Sha256) return "SHA256";
                if (hash == HashType.Sha512) return "SHA512";
                return "UNKNOWN_HASH_TYPE";
            }

            public static HashType GetHashTypeFromHashName(string hashName)
            {
                if (hashName == "SHA1") return HashType.Sha1;
                if (hashName == "SHA256") return HashType.Sha256;
                if (hashName == "SHA512") return HashType.Sha512;
                if (hashName == "MD5") return HashType.Md5;
                return HashType.Unknown;
            }
        }
    }
}
