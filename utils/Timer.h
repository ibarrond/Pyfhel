#ifndef TIMER_H
#define TIMER_H

#include <sys/time.h>
#include <cstddef>

class Timer
{    
    private:
        double m_start;
        double m_stop;
        double my_clock();

    public:
        Timer(bool print=false);
        virtual ~Timer();
        void start();
        void stop();
        double elapsed_time();
        bool flagPrint=false;
};

#endif
