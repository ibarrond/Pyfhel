#include <iostream>
#include <sys/time.h>
#include <cstddef>
#include "Timer.h"

using namespace std;

Timer::Timer(bool print){
    flagPrint=print;
}

Timer::~Timer(){}

void Timer::start() { 
    this->m_start = my_clock();
}

void Timer::stop() { 
    this->m_stop = my_clock();
}

double Timer::elapsed_time() {
    double elapsedTime = this->m_stop - this->m_start;
    if(flagPrint){
        std::cout << "Elapsed time: " << elapsedTime << endl;
    }
   return elapsedTime;
}

double Timer::my_clock() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}
