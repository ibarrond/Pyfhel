#include <Afseal.h>

#include <chrono>	// Measure time
 
#include <cassert>
#include <cstdio>

class timing_map {
	public:
	std::map<std::string, double> timings;
};

class timer {
	public:
	timer(timing_map& newtmap, std::string newname)
		: tmap(newtmap),
		name(newname),
		start(std::clock()) {}

	~timer() {
		tmap.timings[name] = static_cast<double>(std::clock() - start) 
		/ static_cast<double>(CLOCKS_PER_SEC);
		}

	timing_map& tmap;
	std::string name;
	std::clock_t start;
};

timing_map ctx;


int main(int argc, char **argv)
{
    Afseal he;
    // Values for the modulus p (size of p):
    //   - 2 (Binary)
    //   - 257 (Byte)
    //   - 65537 (Word)
    //   - 4294967311 (Long) 
    long p =1964769281;
    long m = 8192;
    long base = 3;
    long sec = 192;
	bool flagBatching=false;

	he.ContextGen(p, m, flagBatching, base, sec);
	std::cout << " Afseal - Contextcreated" << endl;
    he.KeyGen();
	std::cout << " Afseal - Keys Generated" << endl;
    
	int64_t v1=3, v2=-2, vRes;

    Plaintext p1, p2;
    p1 = he.encode(v1);
    p2 = he.encode(v2);

	Ciphertext c1, c2;
    c1 = he.encrypt(p1);
    c2 = he.encrypt(p2);

	std::cout << " Afseal - Encoding and encryption OK" << endl;

    he.saveContext("obj_context.pycon"); 
	std::cout << " Afseal - Context saved" << endl;
	he.savepublicKey("obj_pubkey.pypk");
	std::cout << " Afseal - Public Key Saved" << endl;
    he.savesecretKey("obj_seckey.pysk");
	std::cout << " Afseal - SecretKey Saved" << endl;

	Afseal he2;
    bool done = he2.restoreContext("obj_context.pycon"); 
	std::cout << " Afseal - Context restored " << done << endl;
	he2.restorepublicKey("obj_pubkey.pypk");
	std::cout << " Afseal - Public Key restored " << endl;
    he2.restoresecretKey("obj_seckey.pysk");
	std::cout << " Afseal - SecretKey restored " << endl;

    Plaintext p3, p4;
    p3 = he2.encode(v1);
    p4 = he2.encode(v2);

	Ciphertext c3, c4;
    c3 = he2.encrypt(p3);
    c4 = he2.encrypt(p4);
	std::cout << " Afseal - Encoding and encryption OK" << endl;

};

