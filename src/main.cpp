#include <iostream>
#include <fstream>
#include "ElGamal.h"

std::string readFile(std::string fileName);
void writeFile(std::string fileName, std::string contents);

int main()
{
	std::string inputFile = "test.txt";
	std::string encryptFile = "encrypted.txt";
	std::string decryptFile = "decrypted.txt";


	srand(time(0));
	try
	{
		bigInt privKey = 4;
		auto pubKey = ElGamal::generatePublicKey(privKey);
		ElGamal::printParameters(pubKey, privKey);

		std::cout << "Reading message from " << inputFile << "\n";
		std::string message = readFile(inputFile);//kdljfkdahfkdajfdlkajfkdlajkld";
		std::cout << "Message to be encrypted is " << message.size() << " characters long\n\n";
		std::cout << "Encrypting message..\n";
		auto ciphertext = ElGamal::encrypt(ElGamal::plaintextToHexString(message), pubKey);
		writeFile(encryptFile,  ciphertext);
		std::cout << "Wrote encrypted message to " << encryptFile << "\n";
		std::cout << "Encrypted message is " << ciphertext.size() << " hex characters long\n\n";

		std::cout << "Decrypting message..\n"; 
		auto plaintext = ElGamal::hexStringToPlaintext(ElGamal::decrypt(ciphertext, pubKey, privKey));
		writeFile(decryptFile, plaintext);
		std::cout << "Wrote decrypted message to " << decryptFile << "\n";
		std::cout << "Decrypted message was " << plaintext.size() << " characters long\n\n";

		if(message == plaintext)
		{
			std::cout << "Decrypted message is equal to input\n";
		}
		else
		{
			std::cout << "Decrypted message is NOT equal to input \n";
		}
	}
	catch (std::exception& e)
  	{
    	std::cout << e.what() << '\n';
  	}
  	return 0;

}

std::string readFile(std::string fileName)
{
	std::fstream file;
	file.open(fileName);
	std::stringstream sstream;
	sstream << file.rdbuf();
	file.close();
	return sstream.str();
}

void writeFile(std::string fileName, std::string contents)
{
	std::ofstream file;
	file.open(fileName);
	file << contents;
	file.close();
}
