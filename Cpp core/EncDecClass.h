#pragma once
#include <utility>
#include "osrng.h"
#include <string>
#include <sstream>
using CryptoPP::AutoSeededRandomPool;

#include "Converter.h"
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CTR_Mode;

#include "assert.h"

class EncDecClass
{
private:
	//byte * encryption_key;
	//byte * iv;
public:
	EncDecClass(void);
	~EncDecClass(void);

	void GenerateInitializationVector(byte * iv, int iv_size);

	string EncryptCert(unsigned char* cert,int cert_size, 
					   byte* r, int r_size, 
					   byte* key, int key_size , 
					   byte* iv, int iv_size);

	string EncryptCertAndRa(const unsigned char* cert, int cert_size,
							const byte * ra,			 int ra_size,
						    const byte * key,			 int key_size);

	void CipherPrettyPrinter(string cipher);
	
	void DecryptCertAndRa(string cipher,
						  const byte * key, int key_size,
						  string * decrypted_cert,
						  byte * decrypted_ra, int * decrypted_ra_size);

	void SeparateIvFromCipher(string cipher_plus_iv, string * cipher, string * iv);

	void SeparateCertFromRa(string cert_plus_ra, string * cert, byte * ra);

	void CertStringHexToString(string str_data, string * str_out);

	void RaStringHexToByte(string str_data, byte * byte_data);

	/*std::pair<std::vector<unsigned char>, std::vector<byte> > decryptCert(string decryption, 
																		  byte* key, int key_size, 
																		  byte* iv, int iv_size);*/
	//void decryptCert2(string decryption, 
	//				  byte* key, int key_size, 
	//				  byte* iv, int iv_size,
	//				  string * );
	//void setKey(byte key[], int size);
};


