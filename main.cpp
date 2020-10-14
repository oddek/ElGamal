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


using bigInt = mpz_class;

struct Cipherblock
{
	Cipherblock(mpz_class c1, mpz_class c2): first(c1), second(c2){}

	mpz_class first;
	mpz_class second;


};

// struct PublicKey
// {
// 	BigInt P;
// 	BigInt q; 
// 	BigInt g;
// 	BigInt h;
// };

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
Cipherblock encrypt(mpz_class m);
mpz_class decrypt(Cipherblock c);

//Helpers
mpz_class power(mpz_class x, mpz_class y, mpz_class p);
mpz_class modulo(mpz_class a, mpz_class b);
mpz_class modExp(mpz_class x, mpz_class y, mpz_class p);
std::ostream& operator<<(std::ostream& o, const Cipherblock& c);
void printParameters();
void printNumberDetails(std::string name, bigInt a);

uintmax_t bitCount(mpz_class n);

//Parameters
mpz_class p(t1.p, 16);
mpz_class q = p-1;
mpz_class g(t1.g, 16);
mpz_class x(t1.x, 16);

mpz_class h = power(g, x, p);





int main()
{
	printParameters();


	Cipherblock c = encrypt(168);

	std::cout << c;

	std::cout << decrypt(c) << "\n";

	return 0;

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

void printParameters()
{
	std::cout << "Parameters:\n";
	printNumberDetails("P", p);
	printNumberDetails("q", q);
	printNumberDetails("g", g);
	printNumberDetails("x", x);

}

void fillFromTestVector()
{
	//
}


Cipherblock encrypt(mpz_class m)
{
	mpz_class y(t1.y, 16); //should be picked at random

	mpz_class s = modExp(h, y, p);

	mpz_class c1 = modExp(g, y, p);

	mpz_class c2 = m*s;

	return Cipherblock(c1, c2);
}

mpz_class decrypt(Cipherblock c)
{

	mpz_class s = modExp(c.first, x, p);
	mpz_class sInv = modExp(c.first, q-x, p);

	mpz_class m = modExp(c.second * sInv, 1, p);

	return m;
}

mpz_class modExp(mpz_class x, mpz_class y, mpz_class p)
{
	mpz_class res = 1;
	mpz_class power = x % p;

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
mpz_class power(mpz_class x, mpz_class y, mpz_class p)
{
	mpz_class ret;
	mpz_powm(ret.get_mpz_t(), x.get_mpz_t(), y.get_mpz_t(), p.get_mpz_t());
	return ret;
}

std::ostream& operator<<(std::ostream& o, const Cipherblock& c)
{
	return o << "Cipherblock: \n\tC1:\t" << c.first << "\n\tC2:\t" << c.second << "\n";
}