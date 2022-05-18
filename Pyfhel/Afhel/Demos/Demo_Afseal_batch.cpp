#include "../Afseal.h"

#include <chrono>	// Measure time

#include<fstream>
#include <cassert>
#include <cstdio>
#define VECTOR_SIZE 1000


#if (defined(SEAL_USE_ZSTD))
bool use_zstd = true;
#else
bool use_zstd = false;
#endif

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
    Afhel* he;

	he = new Afseal(); 
    // Values for the modulus p (size of p):
    //   - 2 (Binary)
    //   - 257 (Byte)
    //   - 65537 (Word)
    //   - 4294967311 (Long) 
    uint64_t p =65537;
    size_t n = 4096;
    int sec = 128;

	std::cout << " Afseal - Creating Context" << endl;
	{timer t(ctx, "contextgen");he->ContextGen(scheme_t::bfv, n, 20, -1, sec);}
	std::cout << " Afseal - Context CREATED" << endl;

	//TODO: print parameters

	std::cout << " Afseal - Generating Keys" << endl;
    {timer t(ctx, "keygen"); he->KeyGen();}
    {timer t(ctx, "rotkeygen"); he->rotateKeyGen();}
	std::cout << " Afseal - Keys Generated" << endl;
    
	vector<int64_t> v1;
    vector<int64_t> v2;
    vector<int64_t> vRes;

    for(int64_t i=0; i<1000; i++){
        if(i<VECTOR_SIZE)   { v1.push_back(i);  }
        else                { v1.push_back(0);  }}
    for(int64_t i=0; i<1000; i++){
        if(i<VECTOR_SIZE)   { v2.push_back(2);  }
        else                { v2.push_back(0);  }}
	
    for(int64_t i=0; i<20; i++){
	  std::cout << v1[i] << ' ';
	} std::cout << endl;
	
    for(int64_t i=0; i<20; i++){
	  std::cout << v2[i] << ' ';
	} std::cout << endl;
    
    AfPtxt* p1, *p2, *pres;
	p1 = new AfsealPtxt();
	p2 = new AfsealPtxt();
	pres = new AfsealPtxt();
    AfCtxt *c1, *c2;
	c1 = new AfsealCtxt();
	c2 = new AfsealCtxt();

    he->encode_i(v1, *p1);
    he->encode_i(v2, *p2);

    // Encryption
    {timer t(ctx, "encr11");he->encrypt(*p1, *c1);}
    {timer t(ctx, "encr12");he->encrypt(*p2, *c2);}
    
	
	// Sum
    std::cout << " Afseal - SUM" << endl;
	{timer t(ctx, "add"); he->add(*c1, *c2);}
	{timer t(ctx, "decr1"); he->decrypt(*c1, *pres);}
	he->decode_i(*pres, vRes);
    for(int64_t i=0; i<20; i++){
	  std::cout << vRes[i] << ' ';
	} std::cout << endl;

    // Multiplication
    std::cout << " Afseal - MULT" << endl;
    {timer t(ctx, "encr21");he->encrypt(*p1, *c1);}
    {timer t(ctx, "encr22");he->encrypt(*p1, *c2);}
    {timer t(ctx, "mult");he->multiply(*c1, *c2);}
	{timer t(ctx, "decr2");he->decrypt(*c1,  *pres);}
	he->decode_i(*pres, vRes);
    for(int64_t i=0; i<20; i++){
	  std::cout << vRes[i] << ' ';
	} std::cout << endl;


    // Subtraction
    std::cout << " Afseal - SUB" << endl;
    {timer t(ctx, "encr31");he->encrypt(*p1, *c1);}
    {timer t(ctx, "encr32");he->encrypt(*p1, *c2);}
    {timer t(ctx, "sub");he->sub(*c1, *c2);}
	{timer t(ctx, "decr3");he->decrypt(*c1,  *pres);}
	he->decode_i(*pres, vRes);
    for(int64_t i=0; i<20; i++){
	  std::cout << vRes[i] << ' ';
	} std::cout << endl;

	// Square
    std::cout << " Afseal - SQUARE" << endl;
	{timer t(ctx, "encr41"); he->encrypt(*p1, *c1);}
    {timer t(ctx, "square"); he->square(*c1);}
	{timer t(ctx, "decr4");he->decrypt(*c1,  *pres);}
	he->decode_i(*pres, vRes);
	for(int64_t i=0; i<20; i++){
	  std::cout << vRes[i] << ' ';
	} std::cout << endl;
	
	// Rotation
    std::cout << " Afseal - ROTATE" << endl;
	int rot_pos = 3;
	{timer t(ctx, "encr51"); he->encrypt(*p1, *c1);}
    {timer t(ctx, "rotate"); he->rotate(*c1, rot_pos);}
	{timer t(ctx, "decr4");he->decrypt(*c1,  *pres);}
	he->decode_i(*pres, vRes);
	for(int64_t i=0; i<20; i++){
	  std::cout << vRes[i] << ' ';
	} std::cout << endl;

	// Relinearlization
	he->relinKeyGen();
	he->relinearize(*c1);

	// Relinearlization
	std::cout << " Afseal - SAVE OBJS" << endl;
	string compr_mode = "zstd";
	ofstream f("obj_context.pycon", ios::binary);
    size_t saved1 =he->save_context(f, compr_mode);
	f.close();
	ofstream f2("obj_pubkey.pypk", ios::binary);
	size_t saved2 =he->save_public_key(f2, compr_mode);
	f2.close();
	ofstream f3("obj_seckey.pysk", ios::binary);
    size_t saved3 = he->save_secret_key(f3, compr_mode);
	f3.close();
	ofstream fc("obj_ctxt.cx", ios::binary);
    size_t saved4 = he->save_ciphertext(fc, compr_mode, *c1);
	f3.close();
	
	std::cout << "  - Saved " << saved1 << " " << saved2 << " " << saved3 << " " << saved4 <<endl;

	Afseal he2;
	ifstream f4("obj_context.pycon", ios::binary);
    he2.load_context(f4); 
	std::cout << "  - Loaded context on demo";
	f4.close();
	ifstream f5("obj_pubkey.pypk", ios::binary);
	size_t loaded5 = he2.load_public_key(f5);
	f5.close();
	std::cout << " " << loaded5;
	ifstream f6("obj_seckey.pysk", ios::binary);
    size_t loaded6 = he2.load_secret_key(f6);
	f6.close();
	std::cout << " " << loaded6;
	ifstream fc2("obj_ctxt.cx", ios::binary);
    size_t loaded7 = he->load_ciphertext(fc2, *c1);
	f3.close();
	std::cout << " " << loaded7 <<endl;
	// cleanup
	std::remove( "obj_context.pycon" );
	std::remove( "obj_pubkey.pypk" );
	std::remove( "obj_seckey.pysk" );
	std::remove( "obj_ctxt.cx" );

	// PyPoly
	std::cout << " Afseal - PYPOLY" << endl;
	AfsealPoly* poly1 = new AfsealPoly(*(static_cast<Afseal*>(he)), *(static_cast<AfsealCtxt*>(c1)));
	std::cout << "  - created from ctxt" << endl;
	AfsealPoly* poly2 = new AfsealPoly(*poly1);


	// Timings and results
	auto te =  (ctx.timings["encr11"] + ctx.timings["encr12"] + ctx.timings["encr21"] + ctx.timings["encr22"] + ctx.timings["encr31"] + ctx.timings["encr32"] + ctx.timings["encr41"])/7.0;
	auto td =  (ctx.timings["decr1"] + ctx.timings["decr2"] + ctx.timings["decr3"] + ctx.timings["decr4"])/4.0;
	auto tadd 	= ctx.timings["add"];
	auto tmult 	= ctx.timings["mult"];
	auto tsub  	= ctx.timings["sub"];
	auto tsquare= ctx.timings["square"];
	auto trot= ctx.timings["rotate"];

	std::cout << endl << endl << "RESULTS:" << endl;
	std::cout << " nSlots = " << dynamic_cast<Afseal*>(he)->get_nSlots() << endl;
	std::cout << " Times: " << endl;
	std::cout << "  - Encryption: " <<	te << endl;
	std::cout << "  - Decryption: " <<	td << endl;
	std::cout << "  - Add: " <<	tadd << endl;
	std::cout << "  - Mult: " << tmult << endl;
	std::cout << "  - Sub: " <<	tsub << endl;
	std::cout << "  - Square: " <<	tsquare << endl;
	std::cout << "  - Rotate: " <<	trot << endl;

};

