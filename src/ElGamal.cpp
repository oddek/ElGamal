#include "ElGamal.h"

using namespace ElGamal;

//Constructor for public key struct, generates based on the private key
ElGamal::PublicKey::PublicKey(std::string _p, std::string _g, bigInt privKey)
{
	p = bigInt(_p, 16);
	q = p - 1;
	g = bigInt(_g, 16);
	h = modExp(g, privKey, p);
}

//Main encryption function. Takes and returns a hex-string
std::string ElGamal::encrypt(std::string plaintext, PublicKey pubKey)
{
	//Parse and pad the message, get encryptable blocks instead.
	auto blocks = getMessageBlocks(plaintext, bitCount(pubKey.p));
	std::vector<CipherBlock> cipherBlocks;

	//Encrypt each block separately
	for(auto block : blocks)
	{
		cipherBlocks.push_back(encryptBlock(block, pubKey));

	}
	//Pad (if necessary) and concatenate all cipher blocks to a single string
	auto ciphertext = concatCipherBlocks(cipherBlocks, bitCount(pubKey.p));
	std::cout << "Successfully encrypted " << blocks.size() << " blocks\n";
	return ciphertext;
}

//Separate the input string in hex into blocks relative to the size of P, and add PKCS padding scheme to the blocks
std::vector<bigInt> ElGamal::getMessageBlocks(std::string plaintext, unsigned int pBitSize)
{
	std::vector<bigInt> blocks;

	//Initial blockSize, needs to be within what is allowed by PKCS padding scheme
	unsigned int blockSize = pBitSize/8 - 11*3;

	for(int i = 0; i < plaintext.size(); i += blockSize)
	{
		//Extract substrings of suitable size
		std::string s = plaintext.substr(i, blockSize);
		//Insert a padded block into the array
		blocks.push_back(PKCS(s, pBitSize));
	}
	return blocks;
}

//PKCS#1V1.5 padding scheme
//More detailed description at: https://www.di-mgt.com.au/rsa_alg.html
bigInt ElGamal::PKCS(std::string message, int nBitLen)
{
	std::string binaryMessage = "";
	int keyLen = nBitLen;
	//Check that the block we are about to parse isn't to long
	if(message.size()*8 > keyLen - 11*3) throw std::invalid_argument("Message size to big in PKCS");

	//Length of the random padding, will be keylength - message size - the size of the static flags.
	int pLength = keyLen - message.size()*8 - 3*8;
	//Appending the startflags to the message
	binaryMessage += "00000000";
	binaryMessage += "00000010";
	int counter = 0;
	//Appending random bytes for as long as necessary
	while(binaryMessage.size() < (pLength + 2*8))
	{
		std::string pString = generateRandomNumber(1, pow(2, 8)-1).get_str(2);
		while (pString.size() < 8) pString.insert(0, "0");
		binaryMessage += pString;
	}

	//Appending the flag before the data
	binaryMessage += "00000000";
	//Appending the data
	for(char c : message)
	{
		binaryMessage += std::bitset<8>(c).to_string();
	}
	//Casting the binary message to a bigInt
	bigInt padded(binaryMessage, 2);
	return padded;
}

//Performs the ElGamal encryption on a single block < P
CipherBlock ElGamal::encryptBlock(bigInt m, PublicKey pubKey)
{
	if(m > pubKey.p)
	{
		throw std::invalid_argument( "m larger than p" );
	}
	//Generating random Y for each block
	bigInt y = generateRandomNumber(1, pubKey.q - 1);
	//s = h**y mod p
	bigInt s = modExp(pubKey.h, y, pubKey.p);
	//c1 = g**y mod p
	bigInt c1 = modExp(pubKey.g, y, pubKey.p);
	//c2 = m*s mod p
	bigInt c2 = modExp(m*s, 1, pubKey.p);

	return CipherBlock(c1, c2);
}

//Pad all C1 and C2 so that the length is uniform, and concatonate them into a single string
std::string ElGamal::concatCipherBlocks(std::vector<CipherBlock> cipherBlocks, unsigned int pBitSize)
{
	std::string ciphertext = "";
	unsigned int cSize = pBitSize/4;
	for(auto c : cipherBlocks)
	{
		//Casting the ciphers from bigInt to hex string
		std::string c1 = c.first.get_str(16);
		std::string c2 = c.second.get_str(16);
		//Prepending zeroes until they are of same bit size as p
		while(c1.size() < cSize) c1.insert(0, 1, '0');
		while(c2.size() < cSize) c2.insert(0, 1, '0');

		//Concatenate c1 and c2
		ciphertext += c1;
		ciphertext += c2;
	}

	return ciphertext;
}

//Main decryption function
std::string ElGamal::decrypt(std::string cipherText, PublicKey pubKey, bigInt privKey)
{
	//Parse the string into a vector of cipherblock structs
	auto cipherBlocks = parseCiphertext(cipherText, bitCount(pubKey.p));

	std::string plaintext = "";

	for(auto c : cipherBlocks)
	{
		//Decrypt each block
		bigInt m = decryptBlock(c, pubKey, privKey);
		//Remove PKCS padding
		plaintext += inversePKCS(m, bitCount(pubKey.p));
	}

	std::cout << "Successfully decrypted " << cipherBlocks.size() << " blocks\n";

	return plaintext;
}

//Separate the ciphertext into blocks of C1's and C2's
std::vector<CipherBlock> ElGamal::parseCiphertext(std::string ciphertext, unsigned int pBitSize)
{
	//Only gather substring of same amount of bits as P, and cast them to bigInts.
	//Insert into a vector of cipherblocks

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
bigInt ElGamal::decryptBlock(CipherBlock c, PublicKey pubKey, bigInt privKey)
{
	//s = c1**x mod p
	bigInt s = modExp(c.first, privKey, pubKey.p);
	//sInverse = c1**(q-x) mod p
	bigInt sInv = modExp(c.first, pubKey.q - privKey, pubKey.p);
	//m = (c2*sInverse) mod p
	bigInt m = modExp(c.second * sInv, 1, pubKey.p);

	return m;
}

//Remove the PKCS padding
std::string ElGamal::inversePKCS(bigInt input, int nBitLen)
{
	std::string data = input.get_str(2);
	//A bit of a bad solution here. As the leading zeroes will have disappeared in the casting from string to int
	//we have to prepend them back in.
	data.insert(0, "00000000000000");
	//We then remove them as they are not needed.
	//(This adding and removing is just to make it easier to understand, in real life we would just remove the bits immediately
	data.erase(0, 16);
	//Rest of data read into stringstream
	std::stringstream sstream(data);
	std::string output;
	bool paddingOver = false;

	while(sstream.good())
	{
		//Read out 8 bits at the time from the data
		std::bitset<8> bits;
		sstream >> bits;
		unsigned long i = bits.to_ulong();
		//Checking if we have reached the final all zero byte before the actual data comes
		if(i == 0 && !paddingOver)
		{
			//If that is the case, we of course set the flag that there is no more padding
			paddingOver = true;
			continue;
		}
		//Cast the byte to a char
		unsigned char c = static_cast<unsigned char>(i);
		//If the padding is over, and the character is not 0x00, we of course append it to the datastring we will return.
		if(paddingOver && c != 0x00)
		{
			output += c;
		}
	}
	return output;
}

//Modular exponentiation
//Implemented after the pseudo code in our book.
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
bigInt ElGamal::generateRandomNumber(bigInt min, bigInt max)
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
int ElGamal::bitCount(bigInt n)
{
	int count = 0;
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


