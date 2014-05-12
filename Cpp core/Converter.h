#pragma once
#include <string>
#include <iostream>
#include <strstream>
#include <sstream>
#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "integer.h"
using CryptoPP::Integer;

class Converter
{
public:
	static std::string SecByteBlockToString(SecByteBlock data);
	static std::string ByteToString(byte * data, int length);
	static void FromStringToSecByteblock(std::string data, SecByteBlock* sbb_data, int size);
	static void TestIntegerAndSecByteBlock(Integer, SecByteBlock *);
	static Integer decodeSecByteBlock(SecByteBlock key);
	static SecByteBlock encodeSecByteBlock(Integer key);
	static SecByteBlock encodeSecByteBlockWithLength(Integer key, int length);
	static std::string IntegerToString(Integer a);
};

