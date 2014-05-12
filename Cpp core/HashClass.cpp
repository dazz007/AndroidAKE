#include "HashClass.h"

using namespace std;
int HashClass::size = CryptoPP::SHA1::DIGESTSIZE;
//***************************************************************
byte * HashClass::getSHA1(const byte * input, int length)
{
    CryptoPP::SHA1 sha;
    byte *digest = new byte [length];
    sha.CalculateDigest(digest, input, length);
    return digest;
}
void HashClass::printStringAsHex(byte *m, int length)
{
    for (int i = 0; i < length; i++) {
        cout << hex << (int)m[i] << " ";
    }
}
//***************************************************************
Integer HashClass::getSHA1Integer(string m, Integer r)
{
    byte *encodedMessage = (byte *)m.c_str();
    int messageSize = m.length();
    int rSize = r.MinEncodedSize();
    byte * encodedR = new byte[rSize];
    r.Encode(encodedR, rSize);
    
    byte * hashInput = new byte[rSize + messageSize];
    copy(encodedMessage, encodedMessage + messageSize, hashInput);
    copy(encodedR, encodedR + rSize, hashInput + messageSize);
    byte *hashOutput = getSHA1(hashInput, rSize+messageSize);
    Integer result;
    r.Decode(hashOutput, HashClass::size);
    return r;
}
