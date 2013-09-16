#include <signal.h>
#include <sys/time.h>
#include <string.h>
#include <stdio.h>

int curr_time;

void timer_handler(int signum)
{
  curr_time++;
}

void start_timer()
{
  curr_time = 0;

  struct itimerval timer;
  signal(SIGALRM, timer_handler);

  timer.it_value.tv_sec = 1;
  timer.it_value.tv_usec = 0;
  timer.it_interval.tv_sec = 1;
  timer.it_interval.tv_usec = 0;
  setitimer(ITIMER_REAL, &timer, NULL);
}

