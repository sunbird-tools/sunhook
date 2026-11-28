// The pthread subset shadowhook uses, over SRWLOCK and fiber-local storage. The names are
// remapped so a statically linked winpthreads in the same binary does not collide.

#pragma once

#include <windows.h>

typedef SRWLOCK pthread_mutex_t;
typedef SRWLOCK pthread_rwlock_t;
typedef DWORD pthread_key_t;
typedef DWORD pthread_t;
typedef INIT_ONCE pthread_once_t;

#define PTHREAD_MUTEX_INITIALIZER  SRWLOCK_INIT
#define PTHREAD_RWLOCK_INITIALIZER SRWLOCK_INIT
#define PTHREAD_ONCE_INIT          INIT_ONCE_STATIC_INIT

#define pthread_mutex_init    sh_pthread_mutex_init
#define pthread_mutex_destroy sh_pthread_mutex_destroy
#define pthread_mutex_lock    sh_pthread_mutex_lock
#define pthread_mutex_unlock  sh_pthread_mutex_unlock
#define pthread_rwlock_rdlock sh_pthread_rwlock_rdlock
#define pthread_rwlock_wrlock sh_pthread_rwlock_wrlock
#define pthread_rwlock_unlock sh_pthread_rwlock_unlock
#define pthread_key_create    sh_pthread_key_create
#define pthread_key_delete    sh_pthread_key_delete
#define pthread_getspecific   sh_pthread_getspecific
#define pthread_setspecific   sh_pthread_setspecific
#define pthread_self          sh_pthread_self
#define pthread_once          sh_pthread_once

int sh_pthread_mutex_init(pthread_mutex_t *mutex, const void *attr);
int sh_pthread_mutex_destroy(pthread_mutex_t *mutex);
int sh_pthread_mutex_lock(pthread_mutex_t *mutex);
int sh_pthread_mutex_unlock(pthread_mutex_t *mutex);
int sh_pthread_rwlock_rdlock(pthread_rwlock_t *lock);
int sh_pthread_rwlock_wrlock(pthread_rwlock_t *lock);
int sh_pthread_rwlock_unlock(pthread_rwlock_t *lock);
int sh_pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int sh_pthread_key_delete(pthread_key_t key);
void *sh_pthread_getspecific(pthread_key_t key);
int sh_pthread_setspecific(pthread_key_t key, const void *value);
pthread_t sh_pthread_self(void);
int sh_pthread_once(pthread_once_t *once, void (*init)(void));
