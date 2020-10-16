#include <iostream>
#include <cstdlib>
#include <ctime>
#include <math.h> 
#include <gmp.h>
#include <unistd.h>
#include <algorithm>
#include <gmpxx.h>
#include <bitset>
#include <sstream>
#include <random>
#include <chrono>


//Må finne en god måte å padde c2 på slik at den får uniform lengde uavhengig av P



using bigInt = mpz_class;

struct CipherBlock
{
	CipherBlock(mpz_class c1, mpz_class c2): first(c1), second(c2){}

	mpz_class first;
	mpz_class second;


};

struct PublicKey
 {
 	PublicKey(){};
 	//Constructor for testvectors which use provide hexadecimal strings
 	PublicKey(std::string _p, std::string _g, std::string _h)
 	{
 		p = mpz_class(_p, 16);
 		q = p - 1;
 		g = bigInt(_g, 16);
 		h = bigInt(_h, 16);
 	}
 	bigInt p;
 	bigInt q; 
 	bigInt g;
 	bigInt h;
 };

 struct PrivateKey
 {

 	bigInt x;
 };

struct TestVector
{
	std::string p = "F1B18AE9F7B4E08FDA9A04832F4E919D89462FD31BF12F92791A93519F75076D6CE3942689CDFF2F344CAFF0F82D01864F69F3AECF566C774CBACF728B81A227";
	std::string g = "07";
	std::string y = "688628C676E4F05D630E1BE39D0066178CA7AA83836B645DE5ADD359B4825A12B02EF4252E4E6FA9BEC1DB0BE90F6D7C8629CABB6E531F472B2664868156E20C";
	std::string x = "14E60B1BDFD33436C0DA8A22FDC14A2CCDBBED0627CE68";
	std::string k = "38DBF14E1F319BDA9BAB33EEEADCAF6B2EA5250577ACE7";
	std::string pt = "48656C6C6F207468657265";
	std::string ct1 = "290F8530C2CC312EC46178724F196F308AD4C523CEABB001FACB0506BFED676083FE0F27AC688B5C749AB3CB8A80CD6F7094DBA421FB19442F5A413E06A9772B";
	std:: string ct2 = "1D69AAAD1DC50493FB1B8E8721D621D683F3BF1321BE21BC4A43E11B40C9D4D9C80DE3AAC2AB60D31782B16B61112E68220889D53C4C3136EE6F6CE61F8A23A0";
};

TestVector t1;

//Main functionality
std::vector<CipherBlock> encrypt(std::string message, PublicKey pubKey);
CipherBlock encryptBlock(bigInt m, PublicKey pubKey);
std::string decrypt(std::string cipherText, PublicKey pubKey, bigInt privKey);
mpz_class decryptBlock(CipherBlock c, PublicKey pubKey, bigInt privKey);

//Padding
void addPadding(std::string& s, int blockSize);

//Test
void runTestVectors();
void runTestVector1();
void runTestVector2();

//Helpers
mpz_class power(mpz_class x, mpz_class y, mpz_class p);
mpz_class modulo(mpz_class a, mpz_class b);
mpz_class modExp(mpz_class x, mpz_class y, mpz_class p);
std::ostream& operator<<(std::ostream& o, const CipherBlock& c);
void printParameters(PublicKey pubKey, bigInt privKey);
void printNumberDetails(std::string name, bigInt a);
std::vector<bigInt> getMessageBlocks(std::string message);
std::string plaintextToHexString(std::string plaintext);
std::string hexStringToPlaintext(std::string s);
void printCipherBlock(CipherBlock c);
PublicKey generatePublicKey(bigInt privKey);

uintmax_t bitCount(mpz_class n);


int main()
{

	try
	{
		std::string message = "jf";//kdljfkdahfkdajfdlkajfkdlajkld";

		bigInt privKey = 4;
		
		auto pubKey = generatePublicKey(privKey);

		printParameters(pubKey, privKey);


		auto cipherBlocks = encrypt(message, pubKey);

		for(int i = 0; i < cipherBlocks.size(); i++)
		{
			std::cout << i << ": ";
			printCipherBlock(cipherBlocks.at(i));

		}

		//std::cout << decrypt(c) << "\n";


	}
	catch (std::exception& e)
  	{
    	std::cout << e.what() << '\n';
  	}
  	return 0;

}

PublicKey generatePublicKey(bigInt privKey)
{
	PublicKey pubKey;
	pubKey.p = 7;

	pubKey.q = pubKey.p - 1;
	pubKey.g = 3;
	pubKey.h = modExp(pubKey.g, privKey, pubKey.p);

	return pubKey;
}



std::vector<bigInt> getMessageBlocks(std::string plaintext, unsigned int sizeInBits)
{
	//Kanskje kalle i main
	plaintext = plaintextToHexString(plaintext);

	std::vector<bigInt> blocks;
	//Er usikker på om block size bør være i bits eller bytes i P.
	addPadding(plaintext, sizeInBits);

	for(int i = 0; i < plaintext.size(); i += sizeInBits)
	{

		std::string s = plaintext.substr(i, sizeInBits);

		blocks.push_back(mpz_class(s, 16));

	
	}
	return blocks;
}



void addPadding(std::string& s, int blockSize)
{
	std::stringstream stream;

	stream << std::hex << 0x01;
	for(int i = 0; i < blockSize - ((s.size() + 1) % blockSize); i++)
	{
		stream << std::hex << 0x00;
	}

	s += stream.str();
}




std::vector<CipherBlock> encrypt(std::string message, PublicKey pubKey)
{
	auto blocks = getMessageBlocks(message, bitCount(pubKey.p) - 1);
	std::vector<CipherBlock> cipherBlocks;

	for(auto block : blocks)
	{
		cipherBlocks.push_back(encryptBlock(block, pubKey));

	}

	return cipherBlocks;

	
}

CipherBlock encryptBlock(bigInt m, PublicKey pubKey)
{

	if(m > pubKey.p)
	{
		throw std::invalid_argument( "m larger than p" );
	}
	mpz_class y = 1;//(t1.y, b16); //should be picked at random

	mpz_class s = modExp(pubKey.h, y, pubKey.p);

	mpz_class c1 = modExp(pubKey.g, y, pubKey.p);

	mpz_class c2 = modExp(m*s, 1, pubKey.p);

	return CipherBlock(c1, c2);
}

std::string decrypt(std::string cipherText, PublicKey pubKey, bigInt privKey)
{
	//Parse the string and call decryptblock


	return "";
}

mpz_class decryptBlock(CipherBlock c, PublicKey pubKey, bigInt privKey)
{

	mpz_class s = modExp(c.first, privKey, pubKey.p);
	mpz_class sInv = modExp(c.first, pubKey.q - privKey, pubKey.p);

	mpz_class m = modExp(c.second * sInv, 1, pubKey.p);

	return m;
}

bigInt modExp(bigInt x, bigInt y, bigInt p)
{
	bigInt res = 1;
	bigInt power = x % p;

	std::string n = y.get_str(2);

	for(int i = n.size() - 1; i >= 0; i--)
	{
		if(n.at(i) == '1')
		{
			res = (res * power) % p;
		}
		power = (power * power) % p;
	}

	return res;
}

//Not in use, just here to compare the speed of my own function against it.
bigInt power(bigInt x, bigInt y, bigInt p)
{
	bigInt ret;
	mpz_powm(ret.get_mpz_t(), x.get_mpz_t(), y.get_mpz_t(), p.get_mpz_t());
	return ret;
}














void runTestVector1()
{
	std::string p = "F1B18AE9F7B4E08FDA9A04832F4E919D89462FD31BF12F92791A93519F75076D6CE3942689CDFF2F344CAFF0F82D01864F69F3AECF566C774CBACF728B81A227";
	std::string g = "07";
	std::string y = "688628C676E4F05D630E1BE39D0066178CA7AA83836B645DE5ADD359B4825A12B02EF4252E4E6FA9BEC1DB0BE90F6D7C8629CABB6E531F472B2664868156E20C";
	std::string x = "14E60B1BDFD33436C0DA8A22FDC14A2CCDBBED0627CE68";
	std::string k = "38DBF14E1F319BDA9BAB33EEEADCAF6B2EA5250577ACE7";
	std::string pt = "48656C6C6F207468657265";
	std::string ct1 = "290F8530C2CC312EC46178724F196F308AD4C523CEABB001FACB0506BFED676083FE0F27AC688B5C749AB3CB8A80CD6F7094DBA421FB19442F5A413E06A9772B";
	std:: string ct2 = "1D69AAAD1DC50493FB1B8E8721D621D683F3BF1321BE21BC4A43E11B40C9D4D9C80DE3AAC2AB60D31782B16B61112E68220889D53C4C3136EE6F6CE61F8A23A0";
}

void runTestVector2()
{
	std::string p = "BA4CAEAAED8CBE952AFD2126C63EB3B345D65C2A0A73D2A3AD4138B6D09BD933";
	std::string g = "05";
	std::string y = "60D063600ECED7C7C55146020E7A31C4476E9793BEAED420FEC9E77604CAE4EF";
	std::string x = "1D391BA2EE3C37FE1BA175A69B2C73A11238AD77675932";
	std::string k = "F5893C5BAB4131264066F57AB3D8AD89E391A0B68A68A1";
	std::string pt = "48656C6C6F207468657265";
	std::string ct1 = "32BFD5F487966CEA9E9356715788C491EC515E4ED48B58F0F00971E93AAA5EC7";
	std:: string ct2 = "7BE8FBFF317C93E82FCEF9BD515284BA506603FEA25D01C0CB874A31F315EE68";
}
//https://chromium.googlesource.com/external/github.com/dlitz/pycrypto/+/2.6-winbuild2-wip/lib/Crypto/SelfTest/PublicKey/test_ElGamal.py
void runTestVectors()
{
	runTestVector1();
	runTestVector2();
}



std::string plaintextToHexString(std::string plaintext)
{
	std::stringstream stream;
	for(auto ch : plaintext)
	{
		unsigned long num = ch;
		if(num < 16) stream << 0;
		stream << std::hex << num;
	}
	std::string res(stream.str());
	return res;
}

std::string hexStringToPlaintext(std::string s)
{
	std::string plain = "";
	for(int i = 0; i < s.size(); i+=2)
	{
		char temp = stoul(s.substr(i, 2), 0, 16);
		plain += temp;
	}
	return plain;
}




uintmax_t bitCount(mpz_class n)
{
	uintmax_t count = 0;
	while(n)
	{
		count++;
		n >>= 1;
	}
	return count;
}

void printNumberDetails(std::string name, bigInt a)
{
	std::cout << "\t" << name << ":\n\t\tSize in bits:\t" << bitCount(a) << "\n\t\tNum of digits:\t" << a.get_str().size() << "\n\n\t\t" << a << "\n\n";
}

void printParameters(PublicKey pubKey, bigInt privKey)
{
	std::cout << "Parameters:\n";
	printNumberDetails("P", pubKey.p);
	printNumberDetails("q", pubKey.q);
	printNumberDetails("g", pubKey.g);
	printNumberDetails("x", privKey);

}

void fillFromTestVector()
{
	//
}




void printCipherBlock(CipherBlock c)
{
	std::cout << "CipherBlock: \n";
	printNumberDetails("C1", c.first);
	printNumberDetails("C2", c.second);
}


std::ostream& operator<<(std::ostream& o, const CipherBlock& c)
{
	return o << "CipherBlock: \n\tC1:\t" << c.first << "\n\tC2:\t" << c.second << "\n";
}


