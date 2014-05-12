#include "KeyGenerator.h"

void KeyGenerator::GenerateEphemeralKeyPair(CryptoPP::RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const
{
    Integer a = Integer(rng, keySize);
    byte *aEncoded;
    a.Encode(aEncoded, keySize);
    privateKey = HashClass::getSHA1(aEncoded, keySize);
    CryptoPP::Integer exponent(privateKey, keySize);
    CryptoPP::Integer cA = a_exp_b_mod_c(g, exponent, p);   //ca = g^H(a)
    cA.Encode(publicKey, keySize);
}

void KeyGenerator::GenerateEphemeralKeyPair2(CryptoPP::RandomNumberGenerator &rng, SecByteBlock * eprivateKey, SecByteBlock * epublicKey) const
{
	
	Integer a = Integer(rng, eprivateKey->SizeInBytes());
	byte *aEncoded = new byte[eprivateKey->SizeInBytes()];
	a.Encode(aEncoded, eprivateKey->SizeInBytes());
	byte * privateKey = new byte[eprivateKey->SizeInBytes()];
	privateKey = HashClass::getSHA1(aEncoded, eprivateKey->SizeInBytes());
	eprivateKey->Assign(privateKey, eprivateKey->SizeInBytes());
	//eprivateKey = new SecByteBlock(privateKey, eprivateKey->SizeInBytes());
	CryptoPP::Integer exponent(eprivateKey->BytePtr(), eprivateKey->SizeInBytes());
	CryptoPP::Integer cA = a_exp_b_mod_c(g, exponent, p);   //ca = g^H(a)
	cA.Encode(*epublicKey, epublicKey->SizeInBytes());
}



// K_i = H(K, i)
//byte * KeyGenerator::GenerateKeyFromHashedKey(const byte *key, int random)
//{
//	Integer k = CryptoPP::Integer(key, keySize);
//    k += CryptoPP::Integer(random);
//    byte *encoded = new byte[keySize];
//	k.Encode(encoded, keySize);
//    return HashClass::getSHA1(encoded, keySize);
//}

byte * KeyGenerator::GenerateKeyFromHashedKey(const byte *key, int size, int random)
{
	Integer k = CryptoPP::Integer(key, size);
    k += CryptoPP::Integer(random);
    byte *encoded = new byte[size];
	k.Encode(encoded, size);
    return HashClass::getSHA1(encoded, size);
}


byte * KeyGenerator::GenerateKeyFromHashedKeySec(byte *key, byte * sec_key, int sec_size){
	Integer k = CryptoPP::Integer(key, keySize);
	Integer sec_k = CryptoPP::Integer(sec_key, sec_size);
	k += sec_k;
	byte *encoded = new byte[keySize];
	k.Encode(encoded, keySize);
    return HashClass::getSHA1(encoded, keySize);
}


//cb^exp
byte * KeyGenerator::EstablishSessionKey(byte *ephemeralPrivateKey, byte * ephemeralPublicKey)
{
    CryptoPP::Integer cb = CryptoPP::Integer(ephemeralPrivateKey, keySize);
    CryptoPP::Integer exp = CryptoPP::Integer(ephemeralPublicKey, keySize);
    CryptoPP::Integer key = a_exp_b_mod_c(cb, exp, p);
    byte *sessionKey;
    key.Encode(sessionKey, keySize);
    return sessionKey;
}