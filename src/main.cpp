#include <iostream>
#include <fstream>
#include <chrono>
#include "ElGamal.h"

std::string readFile(std::string fileName);
void writeFile(std::string fileName, std::string contents);

int main()
{
	//Files to be written and read
	std::string inputFile = "test.txt";
	std::string encryptFile = "encrypted.txt";
	std::string decryptFile = "decrypted.txt";

	//Seed random number generator with time.
	srand(time(0));
	try
	{
		//Set privatekey (x)
		bigInt privKey = 79832749832;

		//Generate public key (G, g, q, x)
		auto time1 = std::chrono::high_resolution_clock::now();
		auto pubKey = ElGamal::generatePublicKey(privKey);
		auto time2 = std::chrono::high_resolution_clock::now();
		std::cout << "Key generation took: \n\t" << std::chrono::duration_cast<std::chrono::milliseconds>(time2 - time1).count() << " milliseconds\n";
		ElGamal::printParameters(pubKey, privKey);

		std::cout << "Reading message from " << inputFile << "\n";
		std::string message = readFile(inputFile);
		std::cout << "Message to be encrypted is " << message.size() << " characters long\n\n";

		std::cout << "Encrypting message..\n";
		time1 = std::chrono::high_resolution_clock::now();
		auto ciphertext = ElGamal::encrypt(ElGamal::plaintextToHexString(message), pubKey);
		//STOP AND PRINT ENCRYPT TIME
		time2 = std::chrono::high_resolution_clock::now();
		std::cout << "Encryption took: \n\t" << std::chrono::duration_cast<std::chrono::milliseconds>(time2 - time1).count() << " milliseconds\n";
		writeFile(encryptFile,  ciphertext);
		std::cout << "Wrote encrypted message to " << encryptFile << "\n";
		std::cout << "Encrypted message is " << ciphertext.size() << " hex characters long\n\n";

		std::cout << "Decrypting message..\n";
		time1 = std::chrono::high_resolution_clock::now();
		auto plaintext = ElGamal::hexStringToPlaintext(ElGamal::decrypt(ciphertext, pubKey, privKey));
		time2 = std::chrono::high_resolution_clock::now();
		std::cout << "Decryption took: \n\t" << std::chrono::duration_cast<std::chrono::milliseconds>(time2 - time1).count() << " milliseconds\n";
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
