#include <pthread.h>

int sh_pthread_mutex_init(pthread_mutex_t *mutex, const void *attr) {
  (void)attr;
  InitializeSRWLock(mutex);
  return 0;
}

int sh_pthread_mutex_destroy(pthread_mutex_t *mutex) {
  (void)mutex;
  return 0;
}

int sh_pthread_mutex_lock(pthread_mutex_t *mutex) {
  AcquireSRWLockExclusive(mutex);
  return 0;
}

int sh_pthread_mutex_unlock(pthread_mutex_t *mutex) {
  ReleaseSRWLockExclusive(mutex);
  return 0;
}

// Readers take the lock exclusively, since an SRWLOCK release has to say which mode it holds.
int sh_pthread_rwlock_rdlock(pthread_rwlock_t *lock) {
  AcquireSRWLockExclusive(lock);
  return 0;
}

int sh_pthread_rwlock_wrlock(pthread_rwlock_t *lock) {
  AcquireSRWLockExclusive(lock);
  return 0;
}

int sh_pthread_rwlock_unlock(pthread_rwlock_t *lock) {
  ReleaseSRWLockExclusive(lock);
  return 0;
}

int sh_pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
  DWORD index = FlsAlloc((PFLS_CALLBACK_FUNCTION)destructor);
  if (FLS_OUT_OF_INDEXES == index) return -1;
  *key = index;
  return 0;
}

int sh_pthread_key_delete(pthread_key_t key) {
  return FlsFree(key) ? 0 : -1;
}

void *sh_pthread_getspecific(pthread_key_t key) {
  return FlsGetValue(key);
}

int sh_pthread_setspecific(pthread_key_t key, const void *value) {
  return FlsSetValue(key, (void *)value) ? 0 : -1;
}

pthread_t sh_pthread_self(void) {
  return GetCurrentThreadId();
}

static BOOL CALLBACK sh_pthread_once_run(PINIT_ONCE once, PVOID init, PVOID *context) {
  (void)once, (void)context;
  ((void (*)(void))init)();
  return TRUE;
}

int sh_pthread_once(pthread_once_t *once, void (*init)(void)) {
  return InitOnceExecuteOnce(once, sh_pthread_once_run, (PVOID)init, NULL) ? 0 : -1;
}
