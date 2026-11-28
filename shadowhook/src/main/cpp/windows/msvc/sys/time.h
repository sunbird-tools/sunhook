#pragma once

#include <time.h>
#include <windows.h>
#include <winsock.h>

static inline int gettimeofday(struct timeval *tv, void *tz) {
  (void)tz;
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  uint64_t us = ((((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - 116444736000000000ULL) / 10;
  tv->tv_sec = (long)(us / 1000000);
  tv->tv_usec = (long)(us % 1000000);
  return 0;
}
