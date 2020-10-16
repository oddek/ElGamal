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
#include "ElGamal.h"



int main()
{
	srand(time(0));
	
	try
	{
		std::string message = "jfkd";//kdljfkdahfkdajfdlkajfkdlajkld";
		std::cout << "Message to be encrypted:\n\t" << message << "\n";
		bigInt privKey = 4;
		
		auto pubKey = ElGamal::generatePublicKey(privKey);

		ElGamal::printParameters(pubKey, privKey);


		auto ciphertext = ElGamal::encrypt(ElGamal::plaintextToHexString(message), pubKey);
		std::cout << "Ciphertext: \n\t" << ciphertext << "\n";
		
		
		auto plaintext = ElGamal::decrypt(ciphertext, pubKey, privKey);
		std::cout << "Decrypted:\n\t" << ElGamal::hexStringToPlaintext(plaintext) << "\n";


	}
	catch (std::exception& e)
  	{
    	std::cout << e.what() << '\n';
  	}
  	return 0;

}




