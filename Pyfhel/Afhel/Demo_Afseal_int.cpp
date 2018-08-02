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

	std::cout << " Afseal - Creating Context" << endl;
	{timer t(ctx, "contextgen");he.ContextGen(p, m, flagBatching, base, sec);}
	std::cout << " Afseal - Context CREATED" << endl;

	//TODO: print parameters

	std::cout << " Afseal - Generating Keys" << endl;
    {timer t(ctx, "keygen"); he.KeyGen();}
	std::cout << " Afseal - Keys Generated" << endl;
    
	int64_t v1;
    int64_t v2;
    int64_t vRes;
	Ciphertext k1, k2;

    v1=3;
    v2=-2;
	vRes = 0;
	std::cout << v1 << endl;
	std::cout << v2 << endl;
    
    Plaintext p1, p2;
    p1 = he.encode(v1);
    p2 = he.encode(v2);
    Plaintext p3 = p1 ;

    // Encryption
    {timer t(ctx, "encr11");k1 = he.encrypt(v1);}
    {timer t(ctx, "encr12");k2 = he.encrypt(v2);}
    
	
	// Sum
    std::cout << " Afseal - SUM" << endl;
	{timer t(ctx, "add"); he.add(k1, k2);}
	{timer t(ctx, "decr1"); he.decrypt(k1, vRes);}
	std::cout << vRes << endl;

    // Multiplication
    std::cout << " Afseal - MULT" << endl;
    {timer t(ctx, "encr21");k1 = he.encrypt(v1);}
    {timer t(ctx, "encr22");k2 = he.encrypt(v2);}
    {timer t(ctx, "mult");he.multiply(k1, k2);}
	{timer t(ctx, "decr2"); he.decrypt(k1, vRes);}
    std::cout << vRes << endl;

    // Substraction
    std::cout << " Afseal - SUB" << endl;
    {timer t(ctx, "encr31");k1 = he.encrypt(v1);}
    {timer t(ctx, "encr32");k2 = he.encrypt(v2);}
    {timer t(ctx, "sub");he.sub(k1, k2);}
	{timer t(ctx, "decr3");he.decrypt(k1, vRes);}
	std::cout << vRes << endl;
	
	// Square
    std::cout << " Afseal - SQUARE" << endl;
	{timer t(ctx, "encr41"); k1 = he.encrypt(v1);}
    {timer t(ctx, "square"); he.square(k1);}
    {timer t(ctx, "decr4");he.decrypt(k1, vRes);}
	std::cout << vRes << endl;
	
	// Timings and results
	auto te =  (ctx.timings["encr11"] + ctx.timings["encr12"] + ctx.timings["encr21"] + ctx.timings["encr22"] + ctx.timings["encr31"] + ctx.timings["encr32"] + ctx.timings["encr41"])/7.0;
	auto td =  (ctx.timings["decr1"] + ctx.timings["decr2"] + ctx.timings["decr3"] + ctx.timings["decr4"])/4.0;
	auto tadd 	= ctx.timings["add"];
	auto tmult 	= ctx.timings["mult"];
	auto tsub  	= ctx.timings["sub"];
	auto tsquare= ctx.timings["square"];

	std::cout << endl << endl << "RESULTS:" << endl;
	std::cout << " Times: " << endl;
	std::cout << "  - Encryption: " <<	te << endl;
	std::cout << "  - Decryption: " <<	td << endl;
	std::cout << "  - Add: " <<	tadd << endl;
	std::cout << "  - Mult: " << tmult << endl;
	std::cout << "  - Sub: " <<	tsub << endl;
	std::cout << "  - Square: " <<	tsquare << endl;

};

