#pragma once
#include <iostream>
#include <string>
#include <strstream>
#include "Converter.h"
#include "KeyGenerator.h"
//#include "mac/Hash.h"
#include "EncDecClass.h"
#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "dh.h"
using CryptoPP::DH;

class MutualAuthenticationChip {
private:
	string part;
	int help;
	int keySize;
	Integer p, q, g;
	SecByteBlock * publicKey;
	SecByteBlock * privateKey;
	bool is_initializator;
	SecByteBlock * ephemeralPrivateKey;
	SecByteBlock * ephemeralPublicKeyAnotherParty;
	SecByteBlock * publicKeyAnotherParty;
	SecByteBlock * K_byte;
	byte * Ka;
	byte * Kb;
	byte * Ka_prim;
	byte * Kb_prim;
	byte * rA;
	byte * rB;
	AutoSeededRandomPool  rnd;
	DH dh;
	DH2 * dh2;
	EncDecClass edc;
	KeyGenerator *kg;
	byte * iv;
	int size_of_key_init_vect;
public:
	string cipher;
	MutualAuthenticationChip(bool h): is_initializator(h) {
		Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
				"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
				"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
				"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
				"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
				"DF1FB2BC2E4A4371");

		Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
				  "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
				  "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
			      "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
				  "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
				  "855E6EEB22B3B2E5");

		Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");
		this->p = p;
		this->q = q;
		this->g = g;
		Integer v = ModularExponentiation(g, q, p);
		if(v != Integer::One())
			throw runtime_error("Failed to verify order of the subgroup");
		if(is_initializator){
			part = "A";
			rnd.Reseed(false);
		}else{
			part = "B";
			rnd.Reseed(false);
		}

		dh.AccessGroupParameters().Initialize(this->p, this->q, this->g);

		kg = new KeyGenerator(dh);
		
		dh2 = new DH2(dh);
		keySize = HashClass::size;
		//byte iv_temp[] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
  //      0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f };

		//size_of_key_init_vect = sizeof(iv_temp);
		//iv = new byte[size_of_key_init_vect];
		//memcpy(iv, iv_temp, size_of_key_init_vect);

	}
	SecByteBlock * ephemeralPublicKey;
    Integer getP() { return p; }
    Integer getQ() { return q; }
    Integer getG() { return g; }
	
	
    MutualAuthenticationChip(Integer p, Integer q, Integer g)
    : p(p), q(q), g(g) {}

    void GenerateKeyPairs();
    void GenerateEphemeralKeys();
    void dupa();
    void GetEphemeralPublicKey2(byte * epubKey, size_t & size);
	int CompareRa(byte * decrypted_ra);
	std::string GetEphemeralPublicKey();
    std::string ShowPublicKey();
    std::string ShowPrivateKey();
	void SetEphemeralPublicKeyAnotherParty(std::string str_ephemeralPublicKeyAnotherParty, std::string str_publickKeyAnotherParty);
    int GetKeySize();
	void EncryptCertKey();
	void Generate2(SecByteBlock * publicB, SecByteBlock * privateB);
	void DecryptCertKey(string cipher);
	SecByteBlock GetEphemeralPublicKey2();
	SecByteBlock GetPublicKey();
};

