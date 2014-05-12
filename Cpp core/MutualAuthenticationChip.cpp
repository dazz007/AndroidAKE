#include "MutualAuthenticationChip.h"


void MutualAuthenticationChip::GenerateKeyPairs(){
	privateKey = new SecByteBlock(dh.PrivateKeyLength()); //xA - private key
	publicKey = new SecByteBlock(dh.PublicKeyLength());   //yA = g^xA - public key
	kg->GenerateStaticKeyPair(rnd, *privateKey, *publicKey);
	cout<<"Part: "<<part<<" Zosta³y wygenerowane klucze"<<endl;
}

void MutualAuthenticationChip::GenerateEphemeralKeys(){
	ephemeralPublicKey = new SecByteBlock(dh2->EphemeralPublicKeyLength()); //hA = H(a)
	ephemeralPrivateKey = new SecByteBlock(dh2->EphemeralPrivateKeyLength()); //cA = g^hA
	
    kg->GenerateEphemeralKeyPair2(rnd, ephemeralPrivateKey, ephemeralPublicKey);
	cout<<"Part: "<<part<<" Zosta³y wygenerowane klucze efemeryczne"<<endl;
}

void MutualAuthenticationChip::Generate2(SecByteBlock * pubKeyB, SecByteBlock * privKeyB){
	rnd.Reseed();
	kg->GenerateEphemeralKeyPair2(rnd, privKeyB, pubKeyB);
}

std::string MutualAuthenticationChip::GetEphemeralPublicKey(){
	return Converter::SecByteBlockToString(*ephemeralPublicKey);
}


int MutualAuthenticationChip::GetKeySize(){
	return keySize;
}

std::string MutualAuthenticationChip::ShowPublicKey(){
	string s = Converter::SecByteBlockToString(*publicKey);
	return s;
}

std::string MutualAuthenticationChip::ShowPrivateKey(){
	string s = Converter::SecByteBlockToString(*privateKey);
	return s;
}



void MutualAuthenticationChip::GetEphemeralPublicKey2(byte * epubK, size_t &size){
	//string s = Converter::SecByteBlockToString(*ephemeralPublicKey);
	//cout << "Ephemeral public key in the function: " << std::hex << s << endl;
	//epubK = ephemeralPublicKey->BytePtr();
	//cout << "rozmiar: " << ephemeralPublicKey->size() << endl;
	//cout << "rozmiar2: " << (size_t)ephemeralPublicKey->size() << endl;
	//Integer a;
	//a.Decode(epubK, (size_t)ephemeralPublicKey->size());
	//std::ostrstream oss;
	//oss << std::hex << a;
	//std::string s2(oss.str());
	////std::string s2((char *) epubK, (size_t)ephemeralPublicKey->size());
	//cout << "Ephemeral public key after byte itp: " << std::hex << s2 << endl;
	//std::string s3((char *) epubK, (size_t)ephemeralPublicKey->size());
	//cout << "Ephemeral public s3: " << std::hex << s3 << endl;
	//size = (size_t)ephemeralPublicKey->size();
}


void MutualAuthenticationChip::SetEphemeralPublicKeyAnotherParty(std::string str_ephemeralPublicKeyAnotherParty, 
																 std::string str_publicKeyAnotherParty){
	CryptoPP::Integer Cb;

	CryptoPP::Integer hA;
	CryptoPP::Integer K;
	
	CryptoPP::Integer xA;
	CryptoPP::Integer cb_to_xa;
	//------------------- test
	//CryptoPP::Integer K_test;
	//CryptoPP::Integer Ca_test;
	//CryptoPP::Integer hB_test;
	//SecByteBlock ephemPubB(dh2->EphemeralPublicKeyLength());
	//SecByteBlock ephemPriB(dh2->EphemeralPrivateKeyLength());
	//Generate2(&ephemPubB,&ephemPriB);

	//
	//Ca_test.Decode(ephemeralPublicKey->BytePtr(), ephemeralPublicKey->SizeInBytes());
	//hB_test.Decode(ephemPriB.BytePtr(), ephemPriB.SizeInBytes());
	//---------------------
	cout<<"Part: "<<part<<" otrzyma³ klucz efemeryczny od drugiej strony"<<endl;

	this->K_byte = new SecByteBlock(AES::DEFAULT_KEYLENGTH); //K = cB^hA
	this->Ka = new byte[AES::DEFAULT_KEYLENGTH]; // KA = H(K,1)
	this->Kb = new byte[AES::DEFAULT_KEYLENGTH]; // KB = H(K,2)
	this->Ka_prim = new byte[AES::DEFAULT_KEYLENGTH]; // KA_prim = H(K,3)
	this->Kb_prim = new byte[AES::DEFAULT_KEYLENGTH]; // KB_prim = H(K,4)
	this->rA = new byte[HashClass::size]; //rA = H(cB^xA, KA_prim)
	
	//set public key another party
	publicKeyAnotherParty = new SecByteBlock(dh.PublicKeyLength());
	Converter::FromStringToSecByteblock(str_publicKeyAnotherParty, publicKeyAnotherParty, dh.PublicKeyLength());

	ephemeralPublicKeyAnotherParty = new SecByteBlock(dh2->EphemeralPublicKeyLength());
	Converter::FromStringToSecByteblock(str_ephemeralPublicKeyAnotherParty, ephemeralPublicKeyAnotherParty, dh2->EphemeralPublicKeyLength());
	Cb.Decode(ephemeralPublicKeyAnotherParty->BytePtr(), ephemeralPublicKeyAnotherParty->SizeInBytes());
	//Cb.Decode(ephemPubB.BytePtr(), ephemPubB.SizeInBytes());
	hA.Decode(ephemeralPrivateKey->BytePtr(), ephemeralPrivateKey->SizeInBytes());

	//K_test = a_exp_b_mod_c(Ca_test, hB_test, this->p);
	//cout<<"K test dsadas: "<< K_test<<endl;
	K = a_exp_b_mod_c(Cb, hA, this->p); //K = cB^hA
	cout<<"K partu: "<<part<<" "<<K<<endl;
	K.Encode(*this->K_byte, AES::DEFAULT_KEYLENGTH);

	this->Ka = kg->GenerateKeyFromHashedKey(*this->K_byte, AES::DEFAULT_KEYLENGTH, 1); //KA = H(K,1)
	this->Kb = kg->GenerateKeyFromHashedKey(*this->K_byte, AES::DEFAULT_KEYLENGTH, 2); // KB = H(K,2)
	this->Ka_prim = kg->GenerateKeyFromHashedKey(*this->K_byte, AES::DEFAULT_KEYLENGTH, 3); // KA_prim = H(K,3)
	this->Kb_prim = kg->GenerateKeyFromHashedKey(*this->K_byte, AES::DEFAULT_KEYLENGTH, 4); // KB_prim = H(K,4)

	xA.Decode(this->privateKey->BytePtr(), this->privateKey->SizeInBytes()); //xA - private key
	
	cb_to_xa = a_exp_b_mod_c(Cb, xA, this->p); // cB^xA
	byte * cb_to_xa_byte = new byte[dh2->EphemeralPublicKeyLength()];
	cb_to_xa.Encode(cb_to_xa_byte, dh2->EphemeralPublicKeyLength());

	if(is_initializator)
		rA = kg->GenerateKeyFromHashedKeySec(cb_to_xa_byte, Ka_prim, AES::DEFAULT_KEYLENGTH ); //rA = H(cB^xA, KA_prim)
	else
		rA = kg->GenerateKeyFromHashedKeySec(cb_to_xa_byte, Kb_prim, AES::DEFAULT_KEYLENGTH ); //rB = H(cA^xB, KB_prim)

	cout<<"Part: "<<part<<" wygenerowa³ rA"<<endl;
	Integer test_ra(rA, HashClass::size);
		cout<<"blabla: "<<rA<<endl;
}


void MutualAuthenticationChip::EncryptCertKey(){
	string test = "testowowowona pewnoe jkhsdajgdjhgjbcmxzgigsajdghsma bjjdgsagdj";
	const char* test_c = test.c_str();
	test.size();
	byte * test_b = (byte*)test_c;
	if(is_initializator){
		this->cipher = edc.EncryptCertAndRa(test_b, test.size(),
											rA, HashClass::size,
											Ka, AES::DEFAULT_KEYLENGTH);
	}else{
		this->cipher = edc.EncryptCertAndRa(test_b, test.size(),
											rA, HashClass::size,
											Kb, AES::DEFAULT_KEYLENGTH);
	}
	cout<<"Part: "<<part<<" zaszyfrowa³ certyfikat i rA"<<endl;
}

void MutualAuthenticationChip::DecryptCertKey(string cipher){
	string decrypted_cert;
	byte * decrypted_ra = new byte[HashClass::size];
	byte * rA_prim = new byte[HashClass::size];
	int decrypted_ra_size;
	if(is_initializator){
		edc.DecryptCertAndRa(cipher, Kb, AES::DEFAULT_KEYLENGTH, 
							&decrypted_cert, decrypted_ra, &decrypted_ra_size);

		int n = CompareRa(decrypted_ra);
	if(n == 0){
		cout<<"Po stronie: "<<part<<" Ra takie samo po deszyfracji jak dla strony przeciwnej"<<endl;
	}else{
		cout<<"Cos jest nie tak"<<endl;
	}
	}else{
		edc.DecryptCertAndRa(cipher, Ka, AES::DEFAULT_KEYLENGTH, 
							&decrypted_cert, decrypted_ra, &decrypted_ra_size);
		int n = CompareRa(decrypted_ra);
	if(n == 0){
		cout<<"Po stronie: "<<part<<" Ra takie samo po deszyfracji jak dla strony przeciwnej"<<endl;
	}else{
		cout<<"Cos jest nie tak"<<endl;
	}
	}
		Integer test_ra(rA, HashClass::size);
		Integer decrypted_ra_test(decrypted_ra, HashClass::size);
		cout<<"pierwsze: "<<rA<<endl;
		cout<<"drugie: "<<decrypted_ra_test<<endl;
}

int MutualAuthenticationChip::CompareRa(byte * decrypted_ra){
	Integer yA;
	Integer hB;
	Integer yA_to_hB;
	yA.Decode(publicKeyAnotherParty->BytePtr(), publicKeyAnotherParty->SizeInBytes());
	hB.Decode(ephemeralPublicKey->BytePtr(), ephemeralPublicKey->SizeInBytes());
	yA_to_hB = a_exp_b_mod_c(yA, hB, this->p);
	byte * yA_to_hB_byte = new byte[dh2->EphemeralPublicKeyLength()];
	yA_to_hB.Encode(yA_to_hB_byte, dh2->EphemeralPublicKeyLength());

	byte * to_check = new byte[HashClass::size];

	if(is_initializator)
		to_check = kg->GenerateKeyFromHashedKeySec(yA_to_hB_byte, Ka_prim, AES::DEFAULT_KEYLENGTH ); //rA = H(cB^xA, KA_prim)
	else
		to_check = kg->GenerateKeyFromHashedKeySec(yA_to_hB_byte, Kb_prim, AES::DEFAULT_KEYLENGTH ); //rB = H(cA^xB, KB_prim)

	return memcmp( to_check, decrypted_ra, HashClass::size);
}

SecByteBlock MutualAuthenticationChip::GetEphemeralPublicKey2(){
	return *ephemeralPublicKey;
}

SecByteBlock MutualAuthenticationChip::GetPublicKey(){
	return *publicKey;
}