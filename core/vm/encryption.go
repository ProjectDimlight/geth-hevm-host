package vm

import (
	// "fmt"
    "crypto/aes"
    "crypto/cipher"
    "bytes"
    //"crypto/rsa"
    //"math/big"
)

/*
func initKey(mod []byte, exp []byte, p []byte, q []byte, d []byte) (*rsa.PrivateKey, error) {
    // Convert the byte arrays to big integers
    modInt := new(big.Int).SetBytes(mod)
    expInt := new(big.Int).SetBytes(exp)
    pInt := new(big.Int).SetBytes(p)
    qInt := new(big.Int).SetBytes(q)
    dInt := new(big.Int).SetBytes(d)

    // Create a new RSA private key using the big integers
    rsaKey := &rsa.PrivateKey{
        PublicKey: rsa.PublicKey{
            N: modInt,
            E: 65537,
        },
        D: dInt,
        Primes: []*big.Int{pInt, qInt},
    }

    return rsaKey, nil
}
*/

func encrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    paddedPlaintext := pad(plaintext, block.BlockSize())
    ciphertext := make([]byte, len(paddedPlaintext))
    mode.CryptBlocks(ciphertext, paddedPlaintext)

    return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    extendedCiphertext := extend(ciphertext, block.BlockSize())
    plaintext := make([]byte, len(extendedCiphertext))
    mode.CryptBlocks(plaintext, extendedCiphertext)

    return plaintext[:len(ciphertext)], nil
}

func pad(src []byte, blockSize int) []byte {
    padding := blockSize - len(src) % blockSize
    if padding == blockSize {
        padding = 0
    }
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(src, padtext...)
}

func extend(src []byte, blockSize int) []byte {
    padding := blockSize - len(src) % blockSize
    if padding == blockSize {
        padding = 0
    }
    return src[:len(src) + padding]
}

func encryptAsPage(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
    var tmp = make([]byte, 0, 65536)
    for len(plaintext) > 0 {
        l := MinOf(1024, uint32(len(plaintext)))
        res, err := encrypt(plaintext[0:l], key, iv)
        if err != nil {
            return nil, err
        }
        tmp = append(tmp, res...)
        plaintext = plaintext[l:]
    }
    return tmp, nil
}

func decryptAsPage(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
    var tmp = make([]byte, 0, 65536)
    for len(ciphertext) > 0 {
        l := MinOf(1024, uint32(len(ciphertext)))
        res, err := decrypt(ciphertext[0:l], key, iv)
        if err != nil {
            return nil, err
        }
        tmp = append(tmp, res...)
        ciphertext = ciphertext[l:]
    }
    return tmp, nil
}
