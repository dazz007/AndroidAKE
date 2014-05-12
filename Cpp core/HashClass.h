#pragma once
#include <iostream>
#include <string>
#include "md5.h"
#include "sha.h"
#include "integer.h"
using namespace std;
using CryptoPP::Integer;


class HashClass{
public:
    static byte * getSHA1(const byte * input, int size);
    static Integer getSHA1Integer(string m, Integer r);
    static void printStringAsHex(byte *m, int length);
    static int size;
};

