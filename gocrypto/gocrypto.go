package gocrypto

import(
   "golang.org/x/crypto/bcrypt"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rand"
   "crypto/sha256"
   "errors"
   "io"
   "fmt"
   "encoding/base64"
)

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func hashTo32Bytes(input string) []byte {
    data := sha256.Sum256([]byte(input))
    return data[0:]
}

func EncryptString(plainText string, keyString string) (cipherTextString string, err error) {

    key := hashTo32Bytes(keyString)
    encrypted, err := encryptAES(key, []byte(plainText))
    if err != nil {
        return "", err
    }

    return base64.URLEncoding.EncodeToString(encrypted), nil
}


func encryptAES(key, text []byte) (ciphertext []byte, err error) {
    var block cipher.Block
    if block, err = aes.NewCipher(key); err != nil {
        return nil, err
    }
    ciphertext = make([]byte, aes.BlockSize+len(string(text)))
    iv := ciphertext[:aes.BlockSize]
    fmt.Println(aes.BlockSize)
    if _, err = io.ReadFull(rand.Reader, iv); err != nil {
        return
    }
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
    return
}

func DecryptString(cryptoText string, keyString string) (plainTextString string, err error) {

    encrypted, err := base64.URLEncoding.DecodeString(cryptoText)
    if err != nil {
        return "", err
    }
    if len(encrypted) < aes.BlockSize {
        return "", fmt.Errorf("cipherText too short. It decodes to %v bytes but the minimum length is 16", len(encrypted))
    }

    decrypted, err := decryptAES(hashTo32Bytes(keyString), encrypted)
    if err != nil {
        return "", err
    }

    return string(decrypted), nil
}

func decryptAES(key, ciphertext []byte) (plaintext []byte, err error) {
    var block cipher.Block
    if block, err = aes.NewCipher(key); err != nil {
        return
    }
    if len(ciphertext) < aes.BlockSize {
        err = errors.New("ciphertext too short")
        return
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(ciphertext, ciphertext)
    plaintext = ciphertext
    return
}
