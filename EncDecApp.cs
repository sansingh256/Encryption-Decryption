// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Form1.cs" >
//   All rights reserved.
// </copyright>
// <summary>
//   The form 
//    1.  Create a master key using PBKDF#2,
//    2.  Derive an encryption key and an HMAC key from the master key using PBKDF#2 and one iteration
//    3.  Encrypt  data using CBC chaining mode, and the app must work with 3DES, AES128 and AES256 algorithms. Use a randomly generated IV that is one block in size.
//    4.  Create an HMAC of the IV and the encrypted data.
//    5.  Authenticate if HMAC matches while Decryption.
//    6.  Decrypt authenticated bytes.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
/// <summary>
/// Encryption, Decryption App.
/// </summary>
namespace EncryptionApp
{
    using Microsoft.AspNetCore.Cryptography.KeyDerivation;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Windows.Forms;

    /// <summary>
    /// Form1 Design.
    /// </summary>
    public partial class Form1 : Form
    {
        /// <summary>
        /// Initializing Form1.
        /// </summary>
        public Form1()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Button click event.
        /// </summary>
        private void buttonBrowse_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Multiselect = false;
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                textBoxPath.Text = ofd.FileName;
            }
        }

        /// <summary>
        /// Select radio button for Encrypt.
        /// </summary>
        private void radioEncrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (radioEncrypt.Checked)
            {
                radioDecrypt.Checked = false;
                comboBoxCiphers.Enabled = true;
                comboBoxAlgorithms.Enabled = true;                
                textBoxAlgorithmChoosen.Enabled = false;
                textBoxCyphersChoosen.Enabled = false;
            }
        }
        /// <summary>
        ///  Select radio button for decrypt.
        /// </summary>        
        private void radioDecrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (radioDecrypt.Checked)
            {
                radioEncrypt.Checked = false;
                comboBoxCiphers.Enabled = false;
                comboBoxAlgorithms.Enabled = false;
            }
        }

        /// <summary>
        /// Form load
        /// </summary>
        private void Form1_Load(object sender, EventArgs e)
        {
            radioEncrypt.Checked = true;
        }

        /// <summary>
        /// Main button to start Encrypt or Decrypt.
        /// </summary>
        private void buttonStart_Click(object sender, EventArgs e)
        {
            //Getting input
            if (!File.Exists(textBoxPath.Text))
            {
                MessageBox.Show("File does not exist.");
                return;
            }
            if (string.IsNullOrEmpty(textBoxPassword.Text))
            {
                MessageBox.Show("Password empty. Please enter your  password");
                return;
            }
           
            // Getting File and key to encrypt and decrypt
            try
            {
                Dictionary<string, byte[]> keys = new Dictionary<string, byte[]>();
                byte[] encryptionKey;
                byte[] hmacKey;
                byte[] passwordSalt = GenerateSalt(16);
                byte[] fileContent;
                byte[] fileLength;
                byte[] result;
                fileContent = File.ReadAllBytes(textBoxPath.Text);
                fileLength = new byte[fileContent.Length];
                result = new byte[fileContent.Length];                
                // Encrypt  Data from file                   
                if (radioEncrypt.Checked)
                {                    
                    keys = GetKeys(comboBoxCiphers.Text, passwordSalt, textBoxPassword.Text);
                    keys.TryGetValue("encryptionKey", out encryptionKey);
                    keys.TryGetValue("hmacKey", out hmacKey);
                    if ("AES128".Equals(comboBoxAlgorithms.Text, StringComparison.CurrentCultureIgnoreCase) 
                        || "AES256".Equals(comboBoxAlgorithms.Text, StringComparison.CurrentCultureIgnoreCase))
                    {
                        result = AesEncrypt(fileContent, encryptionKey, comboBoxAlgorithms.Text, hmacKey, comboBoxCiphers.Text);
                    }
                    else
                    {
                        result = TripleDesEncrypt(fileContent, encryptionKey, hmacKey, comboBoxCiphers.Text);
                    }
                }
                // Decrypt data from encrypted file.
                if (radioDecrypt.Checked)
                {

                    DSOFile.OleDocumentProperties dso = new DSOFile.OleDocumentProperties();
                    dso.Open(textBoxPath.Text, false, DSOFile.dsoFileOpenOptions.dsoOptionOpenReadOnlyIfNoWriteAccess);
                    textBoxAlgorithmChoosen.Text = dso.SummaryProperties.Author;
                    textBoxCyphersChoosen.Text = dso.SummaryProperties.Comments;
                    passwordSalt = Convert.FromBase64String(dso.SummaryProperties.Category);
                    dso.Close(true);
                    keys = GetKeys(comboBoxCiphers.Text, passwordSalt, textBoxPassword.Text);
                    keys.TryGetValue("encryptionKey", out encryptionKey);
                    keys.TryGetValue("hmacKey", out hmacKey);                    
                    if ("AES128".Equals(textBoxAlgorithmChoosen.Text, StringComparison.CurrentCultureIgnoreCase) 
                        || "AES256".Equals(textBoxAlgorithmChoosen.Text, StringComparison.CurrentCultureIgnoreCase))
                    {
                        result = AesDecrypt(fileContent, encryptionKey, textBoxAlgorithmChoosen.Text,
                            textBoxCyphersChoosen.Text, hmacKey);
                    }
                    else
                    {
                        result = TripleDesDecrypt(fileContent, encryptionKey,textBoxCyphersChoosen.Text, hmacKey);
                    }
                }
                // Saving result to a new file with the same extension
                string fileExt = Path.GetExtension(textBoxPath.Text);
                SaveFileDialog sfd = new SaveFileDialog();
                sfd.Filter = "Files (*" + fileExt + ") | *" + fileExt;
                if (radioEncrypt.Checked)
                {
                    DSOFile.OleDocumentProperties dso1 = new DSOFile.OleDocumentProperties();
                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        File.WriteAllBytes(sfd.FileName, result);
                        dso1.Open(sfd.FileName.ToString(), false, DSOFile.dsoFileOpenOptions.dsoOptionOpenReadOnlyIfNoWriteAccess);
                        dso1.SummaryProperties.Author = comboBoxAlgorithms.Text;
                        dso1.SummaryProperties.Comments = comboBoxCiphers.Text;
                        dso1.SummaryProperties.Category = Convert.ToBase64String(passwordSalt);
                        dso1.Close(true);
                    }
                }
                if (radioDecrypt.Checked)
                {
                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        File.WriteAllBytes(sfd.FileName, result);
                    }
                }
            }
            catch
            {
                MessageBox.Show("Encryption/Decryption can not be performed. Try again");
                return;
            }
        }
        /// <summary>
        /// Encrypt function for AES and return encrypted bytes.
        /// </summary>              
        private static byte[] AesEncrypt(byte[] plainText, byte[] encryptionKey, string algorithmType, byte[] hmacKey, string shaInput)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = "AES128".Equals(algorithmType, StringComparison.CurrentCultureIgnoreCase)
                ? 128 : "AES256".Equals(algorithmType, StringComparison.CurrentCultureIgnoreCase)
                ? 256 : 0;
            aes.Key = encryptionKey;
            aes.IV = GenerateIV(16);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform crypto = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] cipherText = crypto.TransformFinalBlock(plainText, 0, plainText.Length);
            crypto.Dispose();
            // Creating HMAC by adding  IV and encrypted bytes.
            return string.Equals(shaInput, "HMACSHA256", StringComparison.OrdinalIgnoreCase)
                ? GetHmacForSha256(hmacKey, cipherText, aes.IV) : string.Equals(shaInput, "HMACSHA512", StringComparison.OrdinalIgnoreCase)
                ? GetHmacForSha512(hmacKey, cipherText, aes.IV) : null;
        }

        /// <summary>
        /// Decrypt function for AES and return decrypted bytes.
        /// </summary>        
        public static byte[] AesDecrypt(byte[] cipherText, byte[] encryptionKey, string algorithmType, string shaInput, byte[] hmacKey)
        {

            if (string.Equals(shaInput, "HMACSHA256", StringComparison.OrdinalIgnoreCase))
            {
                using (var hmac = new HMACSHA256(hmacKey))
                {
                    var sentTag = new byte[hmac.HashSize / 8];
                    var calcTag = hmac.ComputeHash(cipherText, 0, cipherText.Length - sentTag.Length);
                    return AuthenticateAndDecryptAes(sentTag, calcTag, cipherText, algorithmType, encryptionKey);

                }
            }
            else if (string.Equals(shaInput, "HMACSHA512", StringComparison.OrdinalIgnoreCase))
            {
                using (var hmac = new HMACSHA512(hmacKey))
                {
                    var sentTag = new byte[hmac.HashSize / 8];
                    var calcTag = hmac.ComputeHash(cipherText, 0, cipherText.Length - sentTag.Length);
                    return AuthenticateAndDecryptAes(sentTag, calcTag, cipherText, algorithmType, encryptionKey);
                }
            }
            return null;
        }

        /// <summary>
        /// Encrypt function for 3DES and return encrypted bytes.
        /// </summary>       
        private static byte[] TripleDesEncrypt(byte[] plainText, byte[] encryptionKey, byte[] hmacKey, string shaInput)
        {
            byte[] cipherText;
            byte[] IV = GenerateIV(16);
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {                
                tdes.Mode = CipherMode.CBC;
                // Create encryptor
                ICryptoTransform encryptor = tdes.CreateEncryptor(encryptionKey, IV);
                // Create MemoryStream 
                using (MemoryStream ms = new MemoryStream())
                {                    
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {                        
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        cipherText = ms.ToArray();
                    }
                }
            }
            return string.Equals(shaInput, "HMACSHA256", StringComparison.OrdinalIgnoreCase)
                ? GetHmacForSha256(hmacKey, cipherText, IV) : string.Equals(shaInput, "HMACSHA512", StringComparison.OrdinalIgnoreCase)
                ? GetHmacForSha512(hmacKey, cipherText, IV) : null;           
        }

        /// <summary>
        /// Decrypt function for 3DES and returns decrypted bytes.
        /// </summary>
        public static byte[] TripleDesDecrypt(byte[] cipherText, byte[] encryptionKey, string shaInput, byte[] hmacKey)
        {            
            if (string.Equals(shaInput, "HMACSHA256", StringComparison.OrdinalIgnoreCase))
            {
                using (var hmac = new HMACSHA256(hmacKey))
                {
                    var sentTag = new byte[hmac.HashSize / 8];
                    var calcTag = hmac.ComputeHash(cipherText, 0, cipherText.Length - sentTag.Length);
                    return AuthenticateAndDecryptTripleDes(sentTag, calcTag, cipherText, encryptionKey);

                }
            }
            else if (string.Equals(shaInput, "HMACSHA512", StringComparison.OrdinalIgnoreCase))
            {
                using (var hmac = new HMACSHA512(hmacKey))
                {
                    var sentTag = new byte[hmac.HashSize / 8];
                    var calcTag = hmac.ComputeHash(cipherText, 0, cipherText.Length - sentTag.Length);
                    return AuthenticateAndDecryptTripleDes(sentTag, calcTag, cipherText, encryptionKey);
                }
            }
            return null;            
        }        
        /// <summary>
        /// Create HMAC with Sha256 of IV and encrypted bytes
        /// </summary>
        private static byte[] GetHmacForSha256(byte[] hmacKey, byte[] cipherText, byte[] IV)
        {
            using (var hmac = new HMACSHA256(hmacKey))
            using (var encryptedBytes = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(encryptedBytes))
                {
                    binaryWriter.Write(IV);
                    binaryWriter.Write(cipherText);
                    binaryWriter.Flush();
                    var tag = hmac.ComputeHash(encryptedBytes.ToArray());
                    
                    // Now PostPend tag
                    binaryWriter.Write(tag);
                }
                return encryptedBytes.ToArray();
            }
        }

        /// <summary>
        /// Create HMAC with Sha512 of IV and encrypted bytes
        /// </summary>
        private static byte[] GetHmacForSha512(byte[] hmacKey, byte[] cipherText, byte[] IV)
        {
            using (var hmac = new HMACSHA512(hmacKey))
            using (var encryptedBytes = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(encryptedBytes))
                {
                    binaryWriter.Write(IV);
                    binaryWriter.Write(cipherText);
                    binaryWriter.Flush();
                    var tag = hmac.ComputeHash(encryptedBytes.ToArray());
                    
                    // Now PostPend tag
                    binaryWriter.Write(Convert.ToBase64String(tag));
                }
                return encryptedBytes.ToArray();
            }
        }

        /// <summary>
        /// Simple Authentication (HMAC) then Decryption (AES) for a secrets 
        /// </summary>
        private static byte[] AuthenticateAndDecryptAes(byte[] sentTag, byte[] calcTag, byte[] cipherText, string algorithmType, byte[] encryptionKey)
        {
            byte[] plainText;
            var ivLength = (128 / 8);
            if (cipherText.Length < sentTag.Length + ivLength)
            {
                return null;
            }
            //Grab Sent Tag
            Array.Copy(cipherText, cipherText.Length - sentTag.Length, sentTag, 0, sentTag.Length);
            //Compare Tag with constant time comparison
            var compare = 0;
            for (var i = 0; i < sentTag.Length; i++)
            {
                compare |= sentTag[i] ^ calcTag[i];
            }
            //if message doesn't authenticate return null
            if (compare != 0)
            {
                return null;
            }
            //Grab IV from message
            var IV = new byte[ivLength];
            Array.Copy(cipherText, 0, IV, 0, IV.Length);
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = "AES128".Equals(algorithmType, StringComparison.CurrentCultureIgnoreCase)
                ? 128 : "AES256".Equals(algorithmType, StringComparison.CurrentCultureIgnoreCase)
                ? 256 : 0;
            aes.Key = encryptionKey;
            aes.IV = IV;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform crypto = aes.CreateDecryptor(aes.Key, aes.IV);
            plainText = crypto.TransformFinalBlock(cipherText, ivLength, cipherText.Length - ivLength - sentTag.Length);
            return plainText;
        }
        
        /// <summary>
        /// Simple Authentication (HMAC) then Decryption (AES) for a secrets 
        /// </summary>
        private static byte[] AuthenticateAndDecryptTripleDes(byte[] sentTag, byte[] calcTag, byte[] cipherText, byte[] encryptionKey)
        {
            byte[] plainText;
            var ivLength = (128 / 8);
            if (cipherText.Length < sentTag.Length + ivLength)
            {
                return null;
            }
            //Grab Sent Tag
            Array.Copy(cipherText, cipherText.Length - sentTag.Length, sentTag, 0, sentTag.Length);
            //Compare Tag with constant time comparison
            var compare = 0;
            for (var i = 0; i < sentTag.Length; i++)
            {
                compare |= sentTag[i] ^ calcTag[i];
            }
            //if message doesn't authenticate return null
            if (compare != 0)
            {
                return null;
            }
            //Grab IV from message
            var IV = new byte[ivLength];
            Array.Copy(cipherText, 0, IV, 0, IV.Length);
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.CBC;
                // Create a decryptor  
                ICryptoTransform decryptor = tdes.CreateDecryptor(encryptionKey, IV);
                // Create the streams used for decryption.  
                using (MemoryStream ms = new MemoryStream(cipherText, ivLength, cipherText.Length - ivLength - sentTag.Length))
                {
                    // Create crypto stream  
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cs))
                            plainText = Encoding.ASCII.GetBytes(reader.ReadToEnd());
                    }
                }
            }
            return plainText;
        }
        /// <summary>
        /// This method is used to drive Master Key, Encryption Key and HMAC Key based on SHA256 or SHA512.
        /// </summary>
        private Dictionary<string, byte[]> GetKeys(string shaInput, byte[] passwordSalt, string password)
        {
            Dictionary<string, byte[]> keys = new Dictionary<string, byte[]>();
            int PBKDF2_ITERATIONS = 64000;
            byte[] masterKey;
            byte[] encryptionKey;
            byte[] hmacKey;
            string encryptionSalt = "encrption key";
            string hmacSalt = "hmac key";
            // 1. Creating Master Key using PBKDF#2
            if ("HMACSHA256".Equals(shaInput, StringComparison.CurrentCultureIgnoreCase))
            {
                masterKey = KeyDerivation.Pbkdf2(
                password: password,
                salt: passwordSalt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: PBKDF2_ITERATIONS,
                numBytesRequested: 16);
                keys.Add("masterKey", masterKey);

                // 2. Driving Encryption Key and HMAC key from the master key using PBKDF#2
                encryptionKey = KeyDerivation.Pbkdf2(
                Convert.ToBase64String(masterKey),
                salt: Encoding.ASCII.GetBytes(encryptionSalt),
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 1,
                numBytesRequested: 16);
                keys.Add("encryptionKey", encryptionKey);

                hmacKey = KeyDerivation.Pbkdf2(
                Convert.ToBase64String(masterKey),
                salt: Encoding.ASCII.GetBytes(hmacSalt),
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 1,
                numBytesRequested: 16);
                keys.Add("hmacKey", hmacKey);
            }
            if ("HMACSHA512".Equals(shaInput, StringComparison.CurrentCultureIgnoreCase))
            {

                masterKey = KeyDerivation.Pbkdf2(
                password: password,
                salt: passwordSalt,
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: PBKDF2_ITERATIONS,
                numBytesRequested: 32);
                keys.Add("masterKey", masterKey);

                // 2. Driving Encryption Key and HMAC key from the master key using PBKDF#2
                encryptionKey = KeyDerivation.Pbkdf2(
                Convert.ToBase64String(masterKey),
                salt: Encoding.ASCII.GetBytes(encryptionSalt),
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: 1,
                numBytesRequested: 32);
                keys.Add("encryptionKey", encryptionKey);

                hmacKey = KeyDerivation.Pbkdf2(
                 Convert.ToBase64String(masterKey),
                salt: Encoding.ASCII.GetBytes(hmacSalt),
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: 1,
                numBytesRequested: 32);
                keys.Add("hmacKey", hmacKey);
            }
            // return masterkey encryption key and hmackey.
            return keys;
        }

        /// <summary>
        /// Generates a random IV value of the specified length.
        /// </summary>
        private static byte[] GenerateIV(int keySize)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[keySize];
                rng.GetBytes(iv);
                return iv;
            }
        }
        /// <summary>
        /// Generates a random salt value of the specified length.
        /// </summary>
        private static byte[] GenerateSalt(int keySize)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] salt = new byte[keySize];
            rng.GetBytes(salt);
            return salt;
        }
    }
}

//---------------------------------------------------- END OF THE CODE----------------------------------------------------
