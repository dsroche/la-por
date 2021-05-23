#include <time.h>
#include <assert.h>

/* note, caller must declare the timespec struct and pass a pointer. */
static void start_time(struct timespec *tp);
static double stop_time(const struct timespec *tp);

static inline void start_time(struct timespec *tp) {
  int res;
  res = clock_gettime(CLOCK_MONOTONIC_RAW, tp);
  assert (res == 0);
}

static inline double stop_time(const struct timespec *tp) {
  struct timespec end;
  int res;
  double diff;
  res = clock_gettime(CLOCK_MONOTONIC_RAW, &end);
  assert (res == 0);
  diff = end.tv_sec - tp->tv_sec;
  diff += (end.tv_nsec - tp->tv_nsec) / 1.e9;
  return diff;
}

static inline void start_cpu_time(struct timespec *tp) {
  int res;
  res = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, tp);
  assert (res == 0);
}

static inline double stop_cpu_time(const struct timespec *tp) {
  struct timespec end;
  int res;
  double diff;
  res = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
  assert (res == 0);
  diff = end.tv_sec - tp->tv_sec;
  diff += (end.tv_nsec - tp->tv_nsec) / 1.e9;
  return diff;
}
