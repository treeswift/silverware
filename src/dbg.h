#ifndef _SILVER_SRC_DBG_H_
#define _SILVER_SRC_DBG_H_

#ifdef _SILVER_DEBUG
#include <stdio.h>

#define _SILVER_LOG(format, ...) { fprintf(_SILVER_DEBUG, format "\n", ##__VA_ARGS__); fflush(_SILVER_DEBUG); }
#else
#define _SILVER_LOG(...)
#endif

#endif /* _SILVER_SRC_DBG_H_ */
