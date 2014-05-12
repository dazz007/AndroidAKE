#include "Converter.h"


std::string Converter::SecByteBlockToString(SecByteBlock data){
	Integer a;
	a.Decode(data.BytePtr(), data.SizeInBytes());
	//cout<< "ze secbyteblock do integera: "<<a<<endl;
	std::ostrstream oss;
	oss << std::hex << a;
	std::string s(oss.str());
	s = s.substr(0, 2*data.SizeInBytes()+1); //Do zapamiêtania. d³ugoœæ stringa z s wynosi 2*d³ugoœæ w bytach plus 1.
	return s;
}

void Converter::FromStringToSecByteblock(std::string data, SecByteBlock * sbb_data, int size){
	Integer a(data.c_str());
	a.Encode(*sbb_data, size);
	//TestIntegerAndSecByteBlock(a, sbb_data);
}

void Converter::TestIntegerAndSecByteBlock(Integer a, SecByteBlock * sbb){
	std::cout<<"Jako integer: "<<std::hex<<a<<std::endl;
	std::string s = SecByteBlockToString(*sbb);
	std::cout<<"Jako string: "<<std::hex<<s<<std::endl;
}

//********************************************************************************************************
Integer Converter::decodeSecByteBlock(SecByteBlock key)
{
    Integer x;
    x.Decode(key.BytePtr(), key.SizeInBytes());
    return x;
}
//********************************************************************************************************
SecByteBlock Converter::encodeSecByteBlock(Integer key)
{
    int length = key.MinEncodedSize();
    byte * byteX;
    key.Encode(byteX, length);
    
    SecByteBlock pubKeyA;
    pubKeyA.Assign(byteX, length);

	std::cout<<"Key: " << key <<std::endl;
	std::cout<<"Decoded: " << decodeSecByteBlock(pubKeyA) <<std::endl;
    //check
    if (key != decodeSecByteBlock(pubKeyA))
        std::cout << "Error while encoding Integer to SecByteBlock" << std::endl;
    
    return pubKeyA;
}

SecByteBlock Converter::encodeSecByteBlockWithLength(Integer key, int length)
{
    //int length = key.MinEncodedSize();
    byte * byteX;
    key.Encode(byteX, length);
    
    SecByteBlock pubKeyA;
    pubKeyA.Assign(byteX, length);

	std::cout<<"Key: " << key <<std::endl;
	std::cout<<"Decoded: " << decodeSecByteBlock(pubKeyA) <<std::endl;
    //check
    if (key != decodeSecByteBlock(pubKeyA))
        std::cout << "Error while encoding Integer to SecByteBlock" << std::endl;
    
    return pubKeyA;
}


std::string Converter::IntegerToString(Integer i)
{
    std::ostringstream oss;
    oss << i;
    return oss.str();
}

std::string Converter::ByteToString(byte * data, int length){
	std::string s(reinterpret_cast<char const*>(data), length);
	return s;
}