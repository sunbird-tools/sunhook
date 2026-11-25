// Copyright (c) 2021-2025 ByteDance Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Created by Kelun Cai (caikelun@bytedance.com) on 2021-04-11.

#include "sh_log.h"

#include <stdarg.h>
#include <stdbool.h>
#ifdef __ANDROID__
#include <android/log.h>
#else
#include <stdio.h>
#include <unistd.h>
#endif

#include "sh_config.h"

sh_log_prio_t sh_log_priority =
#ifdef SH_CONFIG_DEBUG
    SH_LOG_PRIO_INFO
#else
    SH_LOG_PRIO_SILENT
#endif
    ;

bool sh_log_get_debuggable(void) {
  return sh_log_priority <= SH_LOG_PRIO_INFO;
}

void sh_log_set_debuggable(bool debuggable) {
#ifdef SH_CONFIG_DEBUG
  (void)debuggable;
  sh_log_priority = SH_LOG_PRIO_INFO;
#else
  if (__predict_false(debuggable))
    sh_log_priority = SH_LOG_PRIO_INFO;
  else
    sh_log_priority = SH_LOG_PRIO_SILENT;
#endif
}

void sh_log_print(sh_log_prio_t prio, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
#ifdef __ANDROID__
  __android_log_vprint((int)prio, SH_LOG_TAG, fmt, ap);
#else
  (void)prio;
  char buf[1024];
  int len = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
  if (len > 0) {
    size_t n = (size_t)len < sizeof(buf) - 1 ? (size_t)len : sizeof(buf) - 2;
    buf[n] = '\n';
    (void)!write(STDERR_FILENO, buf, n + 1);
  }
#endif
  va_end(ap);
}
