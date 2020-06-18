#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include "RC6.h"

RC6_Cryptor::RC6_Cryptor(const string& Input, const string& Output, const string& Pass)
{
FileIn = Input;
FileOut = Output;
psw = Pass;
}

bool RC6_Cryptor::RC6_Encrypt ()
{
SecByteBlock key(RC6::DEFAULT_KEYLENGTH);
PKCS12_PBKDF<SHA512> pbkdf;
pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

cout << "\nKey: ";
StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));

AutoSeededRandomPool prng;
byte iv[RC6::BLOCKSIZE];
prng.GenerateBlock(iv, sizeof(iv));

ofstream pull(string(FileOut + ".iv").c_str(), ios::out | ios::binary);
pull.write((char*)iv, RC6::BLOCKSIZE);
pull.close();

cout << "\nIV Successfully created: " << FileOut << ".iv" << endl;

try
{
CBC_Mode<RC6>::Encryption encr;
encr.SetKeyWithIV(key, key.size(), iv);

FileSource fs(FileIn.c_str(), true, new StreamTransformationFilter(encr, new FileSink(FileOut.c_str())));
}

catch (const Exception& e)
{
cerr << e.what() << endl;

return false;
}

return true;
}

bool RC6_Cryptor::RC6_Decrypt ()
{
SecByteBlock key(RC6::DEFAULT_KEYLENGTH);
PKCS12_PBKDF<SHA512> pbkdf;
pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

cout << "Key: ";
StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));

cout << endl;

byte iv[RC6::BLOCKSIZE];
ifstream pool(string(FileIn + ".iv").c_str(), ios::in | ios::binary);

if (pool.good())
{
pool.read((char*)&iv, RC6::BLOCKSIZE);
pool.close();
}

else if (pool.bad())
{
cerr << "IV file not found!" << endl;
pool.close();
return false;
}

else
{
cerr << "Incorrect IV file!" << endl;
pool.close();
return false;
}

try
{
CBC_Mode<RC6>::Decryption decr;
decr.SetKeyWithIV(key, key.size(), iv);

FileSource fs(FileIn.c_str(), true, new StreamTransformationFilter(decr, new FileSink(FileOut.c_str())));
}

catch (const Exception& e)
{
cerr << e.what() << endl;

return false;
}

return true;
}
