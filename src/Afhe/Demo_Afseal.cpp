#include <Afseal.h>

#include <chrono>	// Measure time
 
#include <cassert>
#include <cstdio>
#define VECTOR_SIZE 1000

class timing_context {
	public:
	std::map<std::string, double> timings;
};

class timer {
	public:
	timer(timing_context& ctx, std::string name)
		: ctx(ctx),
		name(name),
		start(std::clock()) {}

	~timer() {
		ctx.timings[name] = static_cast<double>(std::clock() - start) 
		/ static_cast<double>(CLOCKS_PER_SEC);
		}

	timing_context& ctx;
	std::string name;
	std::clock_t start;
};

timing_context ctx;


int main(int argc, char **argv)
{
    string fileName = "DemoAfsealEnv";
    Afseal he;
    // Values for the modulus p (size of p):
    //   - 2 (Binary)
    //   - 257 (Byte)
    //   - 65537 (Word)
    //   - 4294967311 (Long) 
    long p =1964769281;
    long m = 16384;
    long base = 2;
    long sec = 192;
	bool flagBatching=true;

	std::cout << " Afseal - Creating Context" << endl;
	he.ContextGen(p, m, flagBatching, base, sec);
	std::cout << " Afseal - Context CREATED" << endl;

	//TODO: print parameters

	std::cout << " Afseal - Generating Keys" << endl;
    he.KeyGen();
	std::cout << " Afseal - Keys Generated" << endl;
    
	vector<int64_t> v1;
    vector<int64_t> v2;
    for(int64_t i=0; i<1000; i++){
        if(i<VECTOR_SIZE)   { v1.push_back(i);  }
        else                { v1.push_back(0);  }}
    for(int64_t i=0; i<1000; i++){
        if(i<VECTOR_SIZE)   { v2.push_back(2);  }
        else                { v2.push_back(0);  }}
	for (auto i: v1)
	  std::cout << i << ' ';
	for (auto i: v2)
	  std::cout << i << ' ';
    Ciphertext k1, k2;
	k1 = he.encrypt(v1);
    k2 = he.encrypt(v2);
    
	
	// Sum
    std::cout << " Afseal - SUM" << endl;
	{timer t(ctx, "add"); he.add(k1, k2);}
    vector<int64_t> vRes = he.decrypt(k1);
    for(int64_t i=0; i<1000; i++){
	  std::cout << vRes[i] << ' ';

    // Multiplication
    std::cout << " Afseal - MULT" << endl;
    k1 = he.encrypt(v1);
    		auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_encr4 = end-start;
    k2 = he.encrypt(v2);
    		auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_encr4 = end-start;
    		auto start = std::chrono::system_clock::now();
    he.multiply(k1, k2);
			auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_mult = end-start;
	vector<int64_t> vRes2 = he.decrypt(k1);
	for (auto i: vRes2)
	  std::cout << i << ' ';
	
    // Substraction
    std::cout << " Afseal - SUB" << endl;
    k1 = he.encrypt(v1);
    		auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_encr4 = end-start;
    k2 = he.encrypt(v2);
    		auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_encr4 = end-start;
    		auto start = std::chrono::system_clock::now();
    he.sub(k1, k2);
			auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_substr = end-start;
    vector<int64_t> vRes3 = he.decrypt(k1);
	for (auto i: vRes3)
	  std::cout << i << ' ';

    // Square
    std::cout << " Afseal - SQUARE" << endl;
    		auto start = std::chrono::system_clock::now();
	k1 = he.encrypt(v1);
    		auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_encr4 = end-start;
    		auto start = std::chrono::system_clock::now();
    he.square(k1);
    		auto end = std::chrono::system_clock::now();
    		std::chrono::duration<double> elapsed_substr = end-start;
    vector<int64_t> vRes4 = he.decrypt(k1);
	for (auto i: vRes4)
	  std::cout << i << ' ';
    std::cout << "END OF DEMO" << endl;
};

