#include "ElGamal.h"

using namespace ElGamal;


ElGamal::PublicKey::PublicKey(std::string _p, std::string _g, bigInt privKey)
{
	p = mpz_class(_p, 16);
	q = p - 1;
	g = bigInt(_g, 16);
	h = modExp(g, privKey, p);
}

//Main encryption function. Takes hex-string
std::string ElGamal::encrypt(std::string plaintext, PublicKey pubKey)
{
	auto blocks = getMessageBlocks(plaintext, bitCount(pubKey.p));
	std::vector<CipherBlock> cipherBlocks;

	for(auto block : blocks)
	{
		cipherBlocks.push_back(encryptBlock(block, pubKey));

	}
	auto ciphertext = concatCipherBlocks(cipherBlocks, bitCount(pubKey.p));
	std::cout << "Successfully encrypted " << blocks.size() << " blocks\n";
	return ciphertext;
}

//Separate the input string in hex into blocks relative to the size of P, and add PKCS padding scheme to the blocks
std::vector<bigInt> ElGamal::getMessageBlocks(std::string plaintext, unsigned int pBitSize)
{
	std::vector<bigInt> blocks;

	unsigned int blockSize = pBitSize/8 - 11*3;

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

//Performs the ElGamal encryption on a single block < P
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

	//std::cout << "Encrypted block with Y =\n\t" << y << "\n";

	return CipherBlock(c1, c2);
}

//Pad all C1 and C2 so that the length is uniform, and concatonate them into a single string
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

//Main decryption function
std::string ElGamal::decrypt(std::string cipherText, PublicKey pubKey, bigInt privKey)
{
	//Parse the string and call decryptblock
	auto cipherBlocks = parseCiphertext(cipherText, bitCount(pubKey.p));

	std::string plaintext = "";
	for(auto c : cipherBlocks)
	{
		bigInt m = decryptBlock(c, pubKey, privKey);

		plaintext += inversePKCS(m, bitCount(pubKey.p));
	}

	std::cout << "Successfully decrypted " << cipherBlocks.size() << " blocks\n";

	return plaintext;
}

//Separate the ciphertext into blocks of C1's and C2's
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

//Decrypt a single block
mpz_class ElGamal::decryptBlock(CipherBlock c, PublicKey pubKey, bigInt privKey)
{

	mpz_class s = modExp(c.first, privKey, pubKey.p);
	mpz_class sInv = modExp(c.first, pubKey.q - privKey, pubKey.p);

	mpz_class m = modExp(c.second * sInv, 1, pubKey.p);

	return m;
}

//Remove the PKCS padding
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

//Modular exponentiation
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

//Gives a public key struct based on the private key
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

//Needed to generate random Y
bigInt ElGamal::generateRandomNumber(mpz_class min, mpz_class max)
{
	return rand() % (max - min + 1) + min;
}

//Helper
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

//Helper
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

//Helper
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

//Printing
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


