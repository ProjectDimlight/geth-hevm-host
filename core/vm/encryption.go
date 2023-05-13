package vm

import (
    "crypto/rsa"
    "math/big"
)

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

func encrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nil, iv, plaintext, nil)
    return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}