#include "EncDecClass.h"

const byte SEPARATOR[] = {0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00};
const string SEPARATOR_IV = "101010101010101010101010101010";
const int IV_SIZE = AES::BLOCKSIZE;
const int KEY_SIZE = AES::DEFAULT_KEYLENGTH;
EncDecClass::EncDecClass(void)
{

}


EncDecClass::~EncDecClass(void)
{
}


//void EncDecClass::setKey(byte key[], int size){
//	encryption_key = new byte[size];
//}

void EncDecClass::GenerateInitializationVector(byte * iv, int iv_size){
	AutoSeededRandomPool rnd;
	rnd.GenerateBlock(iv, iv_size);
}

string EncDecClass::EncryptCertAndRa(const unsigned char *cert, int cert_size,
									 const byte * ra, int ra_size,
									 const byte * key, int key_size){

	string cert_plus_ra;
	string cipher, encoded;
	byte * iv = new byte[IV_SIZE];
	this->GenerateInitializationVector(iv, IV_SIZE);

	HexEncoder encoder;
	encoder.Put(cert, cert_size);
	encoder.Put(SEPARATOR, sizeof(SEPARATOR));
	encoder.Put(ra, ra_size);
	encoder.MessageEnd();

	CryptoPP::lword size = encoder.MaxRetrievable();
	if(size)
	{
		cert_plus_ra.resize(size);		
		encoder.Get((byte*)cert_plus_ra.data(), cert_plus_ra.size());
	}
	try
	{
		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key_size, iv);
		cout<<"cert_plus_ra: "<<cert_plus_ra<<endl;

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(cert_plus_ra, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			)
		);
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}

	
	cipher = cipher + SEPARATOR_IV + Converter::ByteToString(iv, IV_SIZE);
	CipherPrettyPrinter(cipher);
	return cipher;
}

void EncDecClass::CipherPrettyPrinter(string cipher){
	string encoded;
	
	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	//cout << "cipher text: " << encoded << endl;
}

string EncDecClass::EncryptCert(unsigned char *cert ,int cert_size,
								byte *r, int r_size,
								byte * key, int key_size,
								byte * iv, int iv_size){
	
	unsigned char * lc_cert = new unsigned char[cert_size];
	lc_cert = cert;
	unsigned char * lc_r = new unsigned char[r_size];
	lc_r = r;

	string str_cert_plus_r;
	string cipher, encoded;

	HexEncoder encoder;
	encoder.Put(lc_cert, cert_size);
	encoder.Put(SEPARATOR, sizeof(SEPARATOR));
	encoder.Put(r, r_size);
	encoder.MessageEnd();

	int size = encoder.MaxRetrievable();
	if(size)
	{
		str_cert_plus_r.resize(size);		
		encoder.Get((byte*)str_cert_plus_r.data(), str_cert_plus_r.size());
	}

	

	try
	{
		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key_size, iv);


		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(str_cert_plus_r, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}

	return cipher;
}

void EncDecClass::DecryptCertAndRa(string cipher_plus_iv,
								   const byte * key, int key_size,
								   string * decrypted_cert,
								   byte * decrypted_ra, int * decrypted_ra_size){

	string cipher, iv_str, str_sep,
		   str_cert, str_r, recovered;
	SeparateIvFromCipher(cipher_plus_iv, &cipher, &iv_str);
	
	byte * iv = new byte[IV_SIZE];
	iv = (byte*)iv_str.c_str();

	HexEncoder encoder;
	encoder.Put(SEPARATOR, sizeof(SEPARATOR));
	encoder.MessageEnd();

	int size = encoder.MaxRetrievable();
	if(size)
	{
		str_sep.resize(size);		
		encoder.Get((byte*)str_sep.data(), str_sep.size());
	}

	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key_size, iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		std::size_t found = recovered.find(str_sep);
		if (found!=std::string::npos){
			str_cert = recovered.substr(0,found);
			str_r    = recovered.substr(found + sizeof(SEPARATOR)*2,recovered.size());
		}
		
		cout << "recovered text: " << endl;
		cout << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}

	CertStringHexToString(str_cert, decrypted_cert);
	RaStringHexToByte(str_r, decrypted_ra);
	
}

void EncDecClass::SeparateIvFromCipher(string cipher_plus_iv, string * cipher, string * iv){
	
	int start = cipher_plus_iv.find(SEPARATOR_IV);
	if(start != string::npos){
		string cipher2 = cipher_plus_iv.substr(0, start);
		*cipher = cipher2;
		*iv     = cipher_plus_iv.substr(start+SEPARATOR_IV.size(), cipher_plus_iv.size());
	}
	
}


void EncDecClass::RaStringHexToByte(string str_data, byte * byte_data){
	std::stringstream ss;
	string cert;
	unsigned int buffer;
	int offset = 0;
	int i = 0;
	while (offset < str_data.length()) {
	   ss.clear();
	   ss << std::hex << str_data.substr(offset, 2);
	   ss >> buffer;
	   byte_data[i] = static_cast<byte>(buffer);
	   offset += 2;
	   i++;
	}
}

void EncDecClass::CertStringHexToString(string str_data, string * str_out){
	std::stringstream ss;
	std::vector<unsigned char> hexChcert;
	string newString;
	unsigned int buffer;
	int offset = 0;
	int i = 0;

//	for(int i=0; i< str_data.size(); i+=2)
//{
//    string byte = str_data.substr(i,2);
//    char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
//    newString.push_back(chr);
//}
	while (offset < str_data.length()) {
	   ss.clear();
	   ss << std::hex << str_data.substr(offset, 2);
	   ss >> buffer;
	   newString.push_back(static_cast<unsigned char>(buffer));
	   offset += 2;
	}
	str_out = &newString;
	//cout<<"Wynik: "<<*str_out<<endl;
}

//std::pair<std::vector<unsigned char>, std::vector<byte> > EncDecClass::decryptCert(string cert, 
//																				   byte * key, int key_size,
//																				   byte * iv, int iv_size){
//	string recovered;
//	string str_cert, str_r, str_sep;
//
//	//unsigned char * cert_other_party;
//	//byte * r_other_party;
//	string encoded;
//
//	HexEncoder encoder;
//	encoder.Put(SEPARATOR, sizeof(SEPARATOR));
//	encoder.MessageEnd();
//
//	int size = encoder.MaxRetrievable();
//	if(size)
//	{
//		str_sep.resize(size);		
//		encoder.Get((byte*)str_sep.data(), str_sep.size());
//	}
//
//
//	try
//	{
//		CTR_Mode< AES >::Decryption d;
//		d.SetKeyWithIV(key, key_size, iv);
//
//		// The StreamTransformationFilter removes
//		//  padding as required.
//		StringSource s(cert, true, 
//			new StreamTransformationFilter(d,
//				new StringSink(recovered)
//			) // StreamTransformationFilter
//		); // StringSource
//
//		std::size_t found = recovered.find(str_sep);
//		if (found!=std::string::npos){
//			str_cert = recovered.substr(0,found);
//			str_r    = recovered.substr(found + sizeof(SEPARATOR)*2,recovered.size());
//		}
//		
//		//cout << "recovered text: " << endl;
//		//cout << recovered << endl;
//	}
//	catch(const CryptoPP::Exception& e)
//	{
//		cerr << e.what() << endl;
//	}
//
//	std::stringstream ss;
//	std::vector<unsigned char> hexChcert;
//	unsigned int buffer;
//	int offset = 0;
//	int i = 0;
//	while (offset < str_cert.length()) {
//	   ss.clear();
//	   ss << std::hex << str_cert.substr(offset, 2);
//	   ss >> buffer;
//	   hexChcert.push_back(static_cast<unsigned char>(buffer));
//	   offset += 2;
//	}
//
//	offset = 0;
//	std::vector<byte> hexChR;
//	while (offset < str_r.length()) {
//	   ss.clear();
//	   ss << std::hex << str_r.substr(offset, 2);
//	   ss >> buffer;
//	   hexChR.push_back(static_cast<byte>(buffer));
//	   offset += 2;
//	}
//
//	return std::pair<std::vector<unsigned char>, std::vector<byte> >(hexChcert,hexChR);
//}