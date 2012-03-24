#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define FBITS 14

#define INT_TO_FP(n) ((n) * (1 << (FBITS)))
#define FP_TO_INT_FLOOR(x) ((x) / (1 << (FBITS)))
#define FP_TO_INT_ROUND(x) ((x) > 0 ? ((x) + (1 << FBITS) / 2) / (1 << FBITS) : ((x) - (1 << FBITS) / 2) / (1 << FBITS))
#define FP_MULTIPLY(x, y) (((int64_t) (x)) * (y) / (1 << (FBITS)))
#define FP_DIVIDE(x, y) (((int64_t) (x)) * (1 << (FBITS)) / (y))
#define FP_ADD_INT(x, n) ((x) + (n) * (1 << (FBITS)))
#define FP_SUB_INT(x, n) ((x) - (n) * (1 << (FBITS)))
#endif
