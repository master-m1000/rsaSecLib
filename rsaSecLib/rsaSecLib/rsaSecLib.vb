Imports System.Security.Cryptography
Imports System.Text

Public Class rsaSecLib

    Structure KeyPair
        ''' <summary>
        ''' Public key as XML
        ''' </summary>
        ''' <returns></returns>
        Property publicKey As String

        ''' <summary>
        ''' Private key as XML
        ''' </summary>
        ''' <returns></returns>
        Property privateKey As String
    End Structure

    ''' <summary>
    ''' Creates a random RSA key pair.
    ''' </summary>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns></returns>
    Shared Function CreateKeyPair(ByVal keysize As Integer) As KeyPair
        Dim rsaKey As New KeyPair 'Declares return value
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service and Generates random key pair
        rsaKey.publicKey = rsaCryptoProvider.ToXmlString(False) 'Public key to XML
        rsaKey.privateKey = rsaCryptoProvider.ToXmlString(True) 'Private key to XML
        rsaCryptoProvider.Dispose() 'Deallocates ressources
        Return rsaKey
    End Function

    ''' <summary>
    ''' Generates the public key by the private key.
    ''' </summary>
    ''' <param name="privateKeyXml"></param>
    ''' <param name="keysize"></param>
    ''' <returns></returns>
    Shared Function GeneratePublicKeyWithPrivateKey(ByVal privateKeyXml As String, ByVal keysize As Integer) As String
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim publicKey As String 'Declares return value
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        publicKey = rsaCryptoProvider.ToXmlString(False) 'Public key to XML
        Return publicKey
    End Function

    ''' <summary>
    ''' Encrypts a String.
    ''' </summary>
    ''' <param name="DATA">String to encrypt</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Encrypted String</returns>
    Shared Function EncryptString(ByVal DATA As String, ByVal publicKeyXml As String, ByVal keysize As Integer) As String
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim byteData As Byte() = Encoding.UTF8.GetBytes(DATA)  'Write data string into a Byte Array
        Dim encryptedString As String = String.Empty 'Declares return value
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives public key
        encryptedString = Convert.ToBase64String(rsaCryptoProvider.Encrypt(byteData, True)) 'Encrypts data and write it into a Base64 string
        rsaCryptoProvider.Dispose() 'Deallocates ressources
        Return encryptedString
    End Function

    ''' <summary>
    ''' Encrypts a Byte Array.
    ''' </summary>
    ''' <param name="DATA">Byte Array to encrypt</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Encrypted Byte Array</returns>
    Shared Function EncryptByte(ByVal DATA As Byte(), ByVal publicKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim encryptedDATA As Byte() = {0} 'Declares return value
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives public key
        encryptedDATA = rsaCryptoProvider.Encrypt(DATA, True) 'Encrypts data and write it into a Base64 string
        rsaCryptoProvider.Dispose() 'Deallocates ressources
        Return encryptedDATA
    End Function

    ''' <summary>
    ''' Decrypts a String.
    ''' </summary>
    ''' <param name="DATA">String to dencrypt</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Decrypted String</returns>
    Shared Function DecryptString(ByVal DATA As String, ByVal privateKeyXml As String, ByVal keysize As Integer) As String
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim byteData As Byte() = Convert.FromBase64String(DATA) 'Write data Base64 string into a Byte Array
        Dim decryptedString As String = String.Empty 'Declares return value
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        decryptedString = Encoding.Default.GetString(rsaCryptoProvider.Decrypt(byteData, True)) 'Encrypts data and write it into the return value
        rsaCryptoProvider.Dispose() 'Deallocates ressources
        Return decryptedString
    End Function

    ''' <summary>
    ''' Decrypts a Byte Array.
    ''' </summary>
    ''' <param name="DATA">Byte Array to dencrypt</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Decrypted Byte Array</returns>
    Shared Function DecryptByte(ByVal DATA As Byte(), ByVal privateKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim decryptedDATA As Byte() = {0} 'Declares return value
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        decryptedDATA = rsaCryptoProvider.Decrypt(DATA, True) 'Encrypts data and write it into the return value
        rsaCryptoProvider.Dispose() 'Deallocates ressources
        Return decryptedDATA
    End Function

    ''' <summary>
    ''' Signs a String
    ''' </summary>
    ''' <param name="DATA">String to sign</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns></returns>
    Shared Function SignString(DATA As String, ByVal privateKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA servic
        Dim streamDATA As IO.Stream = New IO.MemoryStream(Encoding.UTF8.GetBytes(DATA))  'Writes data string into a Byte Arraye
        Dim signature As Byte() = {0} 'Declares return value
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        signature = rsaCryptoProvider.SignData(streamDATA, GetType(SHA512)) 'Generates signature
        Return signature
    End Function

    ''' <summary>
    ''' Signs a Stream.
    ''' </summary>
    ''' <param name="DATA">Stream to sign</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Signature</returns>
    Shared Function SignData(DATA As IO.Stream, ByVal privateKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim signature As Byte() = {0} 'Declares return value
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        signature = rsaCryptoProvider.SignData(DATA, GetType(SHA512)) 'Generates signature
        Return signature
    End Function

    ''' <summary>
    ''' Verifies a String with a signature.
    ''' </summary>
    ''' <param name="DATA">String to verify</param>
    ''' <param name="signature">The signature</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns></returns>
    Shared Function VerifyString(ByVal DATA As String, signature As Byte(), ByVal publicKeyXml As String, ByVal keysize As Integer) As Boolean
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim verified As Boolean = False 'Declares return valueDim byteData As Byte() = Convert.FromBase64String(DATA) 'Write data Base64 string into a Byte Array
        Dim byteDATA As Byte() = Encoding.UTF8.GetBytes(DATA)  'Write data string into a Byte Arraye
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives private key
        verified = rsaCryptoProvider.VerifyData(byteDATA, GetType(SHA512), signature) 'Generates signature
        Return verified
    End Function

    ''' <summary>
    ''' Verifies a Byte Array with a signature.
    ''' </summary>
    ''' <param name="DATA">Byte Array to verify</param>
    ''' <param name="signature">The signature</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns></returns>
    Shared Function VerifyData(ByVal DATA As Byte(), signature As Byte(), ByVal publicKeyXml As String, ByVal keysize As Integer) As Boolean
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declares RSA service
        Dim verified As Boolean = False 'Declares return value
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives private key
        verified = rsaCryptoProvider.VerifyData(DATA, GetType(SHA512), signature) 'Generates signature
        Return verified
    End Function

End Class