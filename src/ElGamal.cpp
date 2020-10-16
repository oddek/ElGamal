#include "ElGamal.h"

using namespace ElGamal;


ElGamal::PublicKey::PublicKey(std::string _p, std::string _g, bigInt privKey)
	 	{
	 		p = mpz_class(_p, 16);
	 		q = p - 1;
	 		g = bigInt(_g, 16);
	 		h = modExp(g, privKey, p);
	 	}


std::vector<bigInt> ElGamal::getMessageBlocks(std::string plaintext, unsigned int pBitSize)
{
	std::vector<bigInt> blocks;

	unsigned int blockSize = pBitSize*8 - 11*3;

	for(int i = 0; i < plaintext.size(); i += blockSize)
	{

		std::string s = plaintext.substr(i, blockSize);

		blocks.push_back(PKCS(s, pBitSize));
	}
	return blocks;
}



//PKCS#1V1.5 padding scheme
bigInt ElGamal::PKCS(std::string message, int nBitLen)
{
	std::string binaryMessage = "";
	int keyLen = (nBitLen);
	if(message.size()*8 > keyLen - 11*3) throw std::invalid_argument("Message size to big in PKCS");

	int pLength = keyLen - message.size()*8 - 3*8;
	binaryMessage += "00000000";
	binaryMessage += "00000010";
	int counter = 0;
	while(binaryMessage.size() < (pLength + 2*8))
	{
		std::string pString = generateRandomNumber(1, pow(2, 8)-1).get_str(2);
		while (pString.size() < 8) pString.insert(0, "0");
		binaryMessage += pString;
	}

	binaryMessage += "00000000";

	for(char c : message)
	{
		binaryMessage += std::bitset<8>(c).to_string();
	}

	mpz_class padded(binaryMessage, 2);
	return padded;
}

std::string ElGamal::inversePKCS(bigInt input, int nBitLen)
{
	std::string data = input.get_str(2);
	data.insert(0, "00000000000000");
	data.erase(0, 16);

	std::stringstream sstream(data);
	std::string output;
	bool paddingOver = false;
	while(sstream.good())
	{
		std::bitset<8> bits;
		sstream >> bits;
		unsigned long i = bits.to_ulong();
		if(i == 0 && !paddingOver)
		{
			paddingOver = true;
			continue;
		}

		unsigned char c = static_cast<unsigned char>(i);
		if(paddingOver && c != 0x00)
		{
			output += c;
		}
	}
	return output;
}

std::vector<CipherBlock> ElGamal::parseCiphertext(std::string ciphertext, unsigned int pBitSize)
{

	std::vector<CipherBlock> cipherBlocks;

	unsigned int cipherDigitSize = pBitSize/4;

	for(int i = 0; i < ciphertext.size(); i += cipherDigitSize*2)
	{
		auto c1 = ciphertext.substr(i, cipherDigitSize);
		auto c2 = ciphertext.substr(i+cipherDigitSize, cipherDigitSize);

		cipherBlocks.push_back(CipherBlock(bigInt(c1, 16), bigInt(c2, 16)));
	}

	return cipherBlocks;
}


std::string ElGamal::concatCipherBlocks(std::vector<CipherBlock> cipherBlocks, unsigned int pBitSize)
{
	std::string ciphertext = "";
	unsigned int cSize = pBitSize/4;
	for(auto c : cipherBlocks)
	{
		std::string c1 = c.first.get_str(16);		
		std::string c2 = c.second.get_str(16);
		while(c1.size() < cSize) c1.insert(0, 1, '0');
		while(c2.size() < cSize) c2.insert(0, 1, '0');

		ciphertext += c1;
		ciphertext += c2;
	}

	return ciphertext;
}

std::string ElGamal::encrypt(std::string plaintext, PublicKey pubKey)
{

	auto blocks = getMessageBlocks(plaintext, bitCount(pubKey.p));
	std::vector<CipherBlock> cipherBlocks;

	for(auto block : blocks)
	{
		cipherBlocks.push_back(encryptBlock(block, pubKey));

	}


	for(int i = 0; i < cipherBlocks.size(); i++)
	{
		std::cout << i << ": ";
		printCipherBlock(cipherBlocks.at(i));

	}


	auto ciphertext = concatCipherBlocks(cipherBlocks, bitCount(pubKey.p));

	return ciphertext;
}

CipherBlock ElGamal::encryptBlock(bigInt m, PublicKey pubKey)
{

	if(m > pubKey.p)
	{
		throw std::invalid_argument( "m larger than p" );
	}
	mpz_class y = generateRandomNumber(1, pubKey.q - 1);

	mpz_class s = modExp(pubKey.h, y, pubKey.p);

	mpz_class c1 = modExp(pubKey.g, y, pubKey.p);

	mpz_class c2 = modExp(m*s, 1, pubKey.p);

	std::cout << "Encrypted block with Y =\n\t" << y << "\n";

	return CipherBlock(c1, c2);
}

std::string ElGamal::decrypt(std::string cipherText, PublicKey pubKey, bigInt privKey)
{
	//Parse the string and call decryptblock
	auto cipherBlocks = parseCiphertext(cipherText, bitCount(pubKey.p));

	for(int i = 0; i < cipherBlocks.size(); i++)
	{
		std::cout << i << ": ";
		printCipherBlock(cipherBlocks.at(i));

	}

	std::string plaintext = "";
	for(auto c : cipherBlocks)
	{
		bigInt m = decryptBlock(c, pubKey, privKey);

		plaintext += inversePKCS(m, bitCount(pubKey.p));
	}

	return plaintext;
}

mpz_class ElGamal::decryptBlock(CipherBlock c, PublicKey pubKey, bigInt privKey)
{

	mpz_class s = modExp(c.first, privKey, pubKey.p);
	mpz_class sInv = modExp(c.first, pubKey.q - privKey, pubKey.p);

	mpz_class m = modExp(c.second * sInv, 1, pubKey.p);

	return m;
}

bigInt ElGamal::modExp(bigInt x, bigInt y, bigInt p)
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

PublicKey ElGamal::generatePublicKey(bigInt privKey)
{
	PublicKey pubKey
	(
		"F1B18AE9F7B4E08FDA9A04832F4E919D89462FD31BF12F92791A93519F75076D6CE3942689CDFF2F344CAFF0F82D01864F69F3AECF566C774CBACF728B81A227",
		"07",
		privKey
	);

	return pubKey;
}


bigInt ElGamal::generateRandomNumber(int bits)
{
	gmp_randclass rr(gmp_randinit_default);

	sleep(1);
	rr.seed(time(NULL));

	mpz_class ran;
	ran =rr.get_z_bits(bits);
	return ran;
}

bigInt ElGamal::generateRandomNumber(mpz_class min, mpz_class max)
{
	return rand() % (max - min + 1) + min;
}









void ElGamal::runTestVector1()
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

void ElGamal::runTestVector2()
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
void ElGamal::runTestVectors()
{
	runTestVector1();
	runTestVector2();
}



std::string ElGamal::plaintextToHexString(std::string plaintext)
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

std::string ElGamal::hexStringToPlaintext(std::string s)
{
	std::string plain = "";
	for(int i = 0; i < s.size(); i+=2)
	{
		char temp = stoul(s.substr(i, 2), 0, 16);
		plain += temp;
	}
	return plain;
}




uintmax_t ElGamal::bitCount(mpz_class n)
{
	uintmax_t count = 0;
	while(n)
	{
		count++;
		n >>= 1;
	}
	return count;
}

void ElGamal::printNumberDetails(std::string name, bigInt a)
{
	std::cout << "\t" << name << ":\n\t\tSize in bits:\t" << bitCount(a) << "\n\t\tNum of digits:\t" << a.get_str().size() << "\n\n\t\t" << a << "\n\n";
}

void ElGamal::printParameters(PublicKey pubKey, bigInt privKey)
{
	std::cout << "Parameters:\n";
	printNumberDetails("P", pubKey.p);
	printNumberDetails("q", pubKey.q);
	printNumberDetails("g", pubKey.g);
	printNumberDetails("x", privKey);

}

void ElGamal::printCipherBlock(CipherBlock c)
{
	std::cout << "CipherBlock: \n";
	printNumberDetails("C1", c.first);
	printNumberDetails("C2", c.second);
}


