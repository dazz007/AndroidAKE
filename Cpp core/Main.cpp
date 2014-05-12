#include <iostream>
#include "MutualAuthenticationChip.h"
#include "AKETest.h"


int main()
{
	MutualAuthenticationChip macA(true);
	MutualAuthenticationChip macB(false);
	macA.GenerateKeyPairs();
	macB.GenerateKeyPairs();

	//string publicKey = macA.ShowPublicKey();
	//string privateKey = macA.ShowPrivateKey();

	//cout<<"klucz publiczny w stringu: "<< publicKey << endl;
	//cout<<"klucz prywatny w stringu: " <<privateKey << endl;

	macA.GenerateEphemeralKeys();
	macB.GenerateEphemeralKeys();
	macA.SetEphemeralPublicKeyAnotherParty(Converter::SecByteBlockToString(macB.GetEphemeralPublicKey2()), Converter::SecByteBlockToString(macB.GetPublicKey()));
	//macA.SetEphemeralPublicKeyAnotherParty(Converter::SecByteBlockToString(macA.GetEphemeralPublicKey2()));
	macB.SetEphemeralPublicKeyAnotherParty(Converter::SecByteBlockToString(macA.GetEphemeralPublicKey2()), Converter::SecByteBlockToString(macA.GetPublicKey()));

	macA.EncryptCertKey();
	macB.DecryptCertKey(macA.cipher);
	//macB.DecryptCertKey(macA.cipher);
	//macB.EncryptCertKey();
	//macA.DecryptCertKey(macB.cipher);

	//macA.ComputeSessionKey();
	//macB.ComputeSessionKey();
	//macB.DecryptCertKey(macA.cipher);

	system("PAUSE");
}