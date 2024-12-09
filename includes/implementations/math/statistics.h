
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_STATISTICS_INCLUDE_H__
#define __MASTER_STATISTICS_INCLUDE_H__

#include <math.h>
#include <stdlib.h>
#include "../../headers/enumeration/master_enum.h"

#define __MASTER_STATISTICS_CREATE_SOMEFUNC( __MASTER_MACROS_CREATE_FUNC ) \
__MASTER_MACROS_CREATE_FUNC(char,        c)  \
__MASTER_MACROS_CREATE_FUNC(short,       h)  \
__MASTER_MACROS_CREATE_FUNC(long,        l)  \
__MASTER_MACROS_CREATE_FUNC(long long,   ll) \
__MASTER_MACROS_CREATE_FUNC(float,       f)  \
__MASTER_MACROS_CREATE_FUNC(double,      d)  \
__MASTER_MACROS_CREATE_FUNC(long double, ld)

#define __MASTER_STATISTICS_CREATE_SUM_FUNC(type, suff) \
type \
MASTER_sum##suff( const type * array, UI4 __l) { \
	type S = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		S += array[i]; \
	return S; \
}

#define __MASTER_STATISTICS_CREATE_MEAN_FUNC(type, suff) \
type \
MASTER_mean##suff( const type * array, UI4 __l) { \
	return MASTER_sum##suff(array, __l) / __l; \
}

#define __MASTER_STATISTICS_CREATE_FMEAN_FUNC(type, suff) \
type \
MASTER_fmean##suff( const type * array, const type * weights, UI4 __l) { \
	type num = 0; type den = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) { \
		num += array[i] * weights[i]; \
		den += weights[i]; \
	} \
	return num / den; \
} 

#define __MASTER_STATISTICS_CREATE_GEOMETRIC_MEAN_FUNC(type, suff) \
type \
MASTER_geometric_mean##suff( const type * array, UI4 __l) { \
	type P = 1; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		P *= array[i]; \
	return pow(P, 1.0/__l); \
}

#define __MASTER_STATISTICS_CREATE_HARMONIC_MEAN_FUNC(type, suff) \
type \
MASTER_harmonic_mean##suff( const type * array, const type * weights, UI4 __l) { \
	type S = MASTER_sum##suff(weights, __l); \
	type T = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		T += weights[i] / array[i]; \
	return S / T; \
}

#define __MASTER_STATISTICS_CREATE_MEDIAN_FUNC(type, suff) \
type \
MASTER_median##suff( type * array, UI4 __l ) { \
	return (__l % 2 == 0) ? (array[__l / 2 - 1] + array[__l / 2]) / 2.0 : array[__l / 2]; }

#define __MASTER_STATISTICS_CREATE_MEDIAN_LOW_FUNC(type, suff) \
type \
MASTER_median##suff##_low( type * array, UI4 __l ) { \
	return (__l % 2 == 0) ? array[__l / 2 - 1] : array[__l / 2]; }

#define __MASTER_STATISTICS_CREATE_MEDIAN_HIGH_FUNC(type, suff) \
type \
MASTER_median##suff##_high( type * array, UI4 __l ) { \
	return array[__l / 2]; }

// array must be sorted
#define __MASTER_STATISTICS_CREATE_MEDIAN_GROUPED_FUNC(type, suff) \
type \
MASTER_median_grouped##suff( type * array, UI4 __l, type interval ) { \
	type x = array[__l / 2]; \
	UI4 i = __l, j = __l, k; \
	for (k = 0; k < __l; k++) \
		if (array[k] >= x) { \
			i = k; \
			break; \
		} \
	for (k = i; k < __l; k++) \
		if (array[k] > x) { \
			j = k; \
			break; \
		} \
	return (x - interval / 2.0) + interval * (__l / 2 - i) / (j - i); \
}

#define __MASTER_STATISTICS_CREATE_MODE_FUNC(type, suff) \
type \
MASTER_mode##suff( type * array, UI4 __l ) { \
	type most_common = -1; \
	UI4 repeates = 0; \
	type * unical = (type *)malloc(0); \
	UI4 * count  = (UI4 *)malloc(0); \
	UI4 i = 0, j, len = 0; \
	UI1 is_inlist; \
	for (; i < __l; i++) { \
		is_inlist = 0; \
		for (j = 0; j < len; j++) { \
			if (unical[j] == array[i]) { \
				count[j]++; \
				is_inlist = 1; \
				break; \
			} \
		} \
		if (is_inlist == 0) { \
			unical = (type *)realloc(unical, ++len * sizeof(type)); \
			count  = (UI4 *)realloc(count,  len * sizeof(UI4)); \
			unical[len - 1] = array[i]; \
			count[len - 1] = 1; \
		} \
	} \
	for (i = 0; i < len; i++) \
		if (count[i] > repeates) { \
			most_common = unical[i]; \
			repeates = count[i]; \
		} \
	\
	free(unical); \
	free(count); \
	\
	return most_common; \
}

// USING MALLOC! UNSAFE
#define __MASTER_STATISTICS_CREATE_MULTI_MODE_FUNC(type, suff) \
type * \
MASTER_multi_mode##suff( const type * array, UI4 __l, UI4 * len_out ) { \
	UI4 repeates = 0; \
	type * array_out; \
	UI4 compared_count = 0; \
	UI4 next_compared_index = 0; \
	type * unical = (type *)malloc(0); \
	UI4 * count  = (UI4 *)malloc(0); \
	UI4 i = 0, j, len = 0; \
	UI1 is_inlist; \
	for (; i < __l; i++) { \
		is_inlist = 0; \
		for (j = 0; j < len; j++) { \
			if (unical[j] == array[i]) { \
				count[j]++; \
				is_inlist = 1; \
				break; \
			} \
		} \
		if (is_inlist == 0) { \
			unical = (type *)realloc(unical, ++len * sizeof(type)); \
			count  = (UI4 *)realloc(count,  len * sizeof(UI4)); \
			unical[len - 1] = array[i]; \
			count[len - 1] = 1; \
		} \
	} \
	for (i = 0; i < len; i++) \
		if (count[i] > repeates) \
			repeates = count[i]; \
	\
	for (i = 0; i < len; i++) \
		if (count[i] == repeates) \
			compared_count++; \
	*len_out = compared_count; \
	array_out = (type *)malloc(sizeof(type) * compared_count); \
	for (i = 0; i < len; i++) \
		if (count[i] == repeates) \
			array_out[next_compared_index++] = unical[i]; \
	\
	free(unical); \
	free(count); \
	return array_out; \
}

// mu = sum(array) / len(array)
#define __MASTER_STATISTICS_CREATE_PSTDEV_FUNC(type, suff) \
type \
MASTER_pstdev##suff( const type * array, UI4 __l, type mu) { \
	type S = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		S += pow(array[i] - mu, 2); \
	return sqrt(S/__l); \
}

// mu = sum(array) / len(array)
#define __MASTER_STATISTICS_CREATE_PVARIANCE_FUNC(type, suff) \
type \
MASTER_pvariance##suff( const type * array, UI4 __l, type mu) { \
	type S = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		S += pow(array[i] - mu, 2); \
	return S/__l; \
}

// xbar = sum(array) / len(array)
#define __MASTER_STATISTICS_CREATE_STDEV_FUNC(type, suff) \
type \
MASTER_stdev##suff( const type * array, UI4 __l, type xbar) { \
	type S = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		S += pow(array[i] - xbar, 2); \
	return sqrt(S/(__l - 1)); \
}

// xbar = sum(array) / len(array)
#define __MASTER_STATISTICS_CREATE_VARIANCE_FUNC(type, suff) \
type \
MASTER_variance##suff( const type * array, UI4 __l, type xbar) { \
	type S = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		S += pow(array[i] - xbar, 2); \
	return S/(__l - 1); \
}

// array must be sorted
// USING MALLOC! UNSAFE (outlen = n - 1)
#define __MASTER_STATISTICS_CREATE_QUANTILES_FUNC(type, suff) \
type * \
MASTER_quantiles##suff( const type * array, UI4 __l, UI4 n, const UI1 method) { \
	type probs[__l]; \
	type q; \
	type * quantiles; \
	UI4 i = 0, k, ptr = 0; \
	switch (method) { \
		case MASTER_quantile_EXCLUSIVE: \
			for (; i < __l; i++) \
				probs[i] = (i + (type)1) / (__l + (type)1); \
			break; \
		case MASTER_quantile_INCLUSIVE: \
			for (; i < __l; i++) \
				probs[i] = i / (__l - (type)1); \
			break; \
		default: return (type *)NULL; \
	} \
	quantiles = (type *)malloc(sizeof(type) * (n - 1)); \
	for (i = 1; i < n; i++) { \
		q = (type)i / (type)n; \
		k = 0; \
		while ((k < __l) && (probs[k] < q)) k++; \
		if (k == __l) k = __l - 1; \
		if (probs[k] == q) \
			quantiles[ptr++] = array[k]; \
		else quantiles[ptr++] = array[k - 1] + (array[k] - array[k - 1]) * (q - probs[k - 1]) / (probs[k] - probs[k - 1]); \
	} \
	return quantiles; \
}

typedef enum {
	MASTER_quantile_EXCLUSIVE = 0x20,
	MASTER_quantile_INCLUSIVE = 0x40,
} MASTER_quantile_methods;

#define __MASTER_STATISTICS_CREATE_COVARIANCE_FUNC(type, suff) \
type \
MASTER_covariance##suff( const type * array_1, const type * array_2, UI4 __l) { \
	type x_mean = MASTER_sum##suff(array_1, __l) / __l; \
	type y_mean = MASTER_sum##suff(array_2, __l) / __l; \
	type covariance = 0; \
	UI4 i = 0; \
	for (; i < __l; i++) \
		covariance += (array_1[i] - x_mean) * (array_2[i] - y_mean); \
	return covariance / (__l - 1); \
}

#define __MASTER_STATISTICS_CREATE_PEARSON_CORRELATION_FUNC(type, suff) \
type \
MASTER_pearson_correlation##suff( const type * array_1, const type * array_2, UI4 __l) { \
	type x_mean = MASTER_sum##suff(array_1, __l) / (type)__l; \
	type y_mean = MASTER_sum##suff(array_2, __l) / (type)__l; \
	type sum_xy = 0, sum_x_sq = 0, sum_y_sq = 0; \
	UI4 i; \
	for (i = 0; i < __l; i++) \
		sum_xy += (array_1[i] - x_mean) * (array_2[i] - y_mean); \
	for (i = 0; i < __l; i++) \
		sum_x_sq += pow(array_1[i] - x_mean, 2); \
	for (i = 0; i < __l; i++) \
		sum_y_sq += pow(array_2[i] - y_mean, 2); \
	return sum_xy / pow(sum_x_sq * sum_y_sq, 0.5); \
}

// array must be sorted
// unsafe, but private
#define __MASTER_STATISTICS_CREATE_CORRELATION_PRIVATE_RANK_DATA_FUNC(type, suff) \
static type * \
__MASTER_rank_data##suff( const type * array, UI4 __l) { \
	type data [__l]; \
	UI4 index[__l]; \
	type rank_sum, avg_rank; \
	UI4 i, j, k; \
	for (i = 0; i < __l; i++) { \
		data[i] = array[i]; \
		index[i] = i; \
	} \
	type * ranks = (type *)calloc(__l, sizeof(type)); \
	i = 0; \
	while (i < __l) { \
		j = i; \
		while ((j < __l - 1) && (data[j] == data[j + 1])) j++; \
		rank_sum = 0; \
		for (k = i; k < j + 1; k++) \
			rank_sum += k + 1; \
		avg_rank = rank_sum / (j - i + 1); \
		for (k = i; k < j + 1; k++) \
			ranks[index[k]] = avg_rank; \
		i = j + 1; \
	} \
	return ranks; \
}

#define __MASTER_STATISTICS_CREATE_SPEARMAN_CORRELATION_FUNC(type, suff) \
type \
MASTER_spearman_correlation##suff( const type * array_1, const type * array_2, UI4 __l) { \
	type * rank_x = __MASTER_rank_data##suff(array_1, __l); \
	type * rank_y = __MASTER_rank_data##suff(array_2, __l); \
	type res = MASTER_pearson_correlation##suff(rank_x, rank_y, __l); \
	free(rank_x); \
	free(rank_y); \
	return res; \
}

// arrays must be sorted
#define __MASTER_STATISTICS_CREATE_CORRELATION_FUNC(type, suff) \
type \
MASTER_correlation##suff( const type * array_1, const type * array_2, UI4 __l, const UI1 method) { \
	switch (method) { \
		case MASTER_correlation_LINEAR: return MASTER_pearson_correlation##suff(array_1, array_2, __l); \
		case MASTER_correlation_RANKED: return MASTER_spearman_correlation##suff(array_1, array_2, __l); \
		default: return (type)0; \
	} \
}

typedef enum {
	MASTER_correlation_LINEAR = 0x10,
	MASTER_correlation_RANKED = 0x80,
} MASTER_correlation_methods;

#define __MASTER_STATISTICS_CREATE_LINEAR_REGRESSION_FUNC(type, suff) \
type \
MASTER_linear_regression##suff( const type * array_1, const type * array_2, UI4 __l, const UI1 proportional, type * intercept) { \
	UI4 i; \
	type num = 0, den = 0; \
	type c_slope, c_intercept = 0; \
	if (proportional) { \
		for (i = 0; i < __l; i++) { \
			num += array_1[i] * array_2[i]; \
			den += pow(array_1[i], 2); \
		} \
		c_slope = num / den; \
	} else { \
		type x_mean = MASTER_sum##suff(array_1, __l) / __l; \
		type y_mean = MASTER_sum##suff(array_2, __l) / __l; \
		for (i = 0; i < __l; i++) { \
			num += (array_1[i] - x_mean) * (array_2[i] - y_mean); \
			den += pow(array_1[i] - x_mean, 2); \
		} \
		c_slope = num / den; \
		c_intercept = y_mean - c_slope * x_mean; \
	} \
	if (intercept != NULL) \
		*intercept = c_intercept; \
	return c_slope; \
}

__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_SUM_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_MEAN_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_FMEAN_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_GEOMETRIC_MEAN_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_HARMONIC_MEAN_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_MEDIAN_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_MEDIAN_LOW_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_MEDIAN_HIGH_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_MEDIAN_GROUPED_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_MODE_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_MULTI_MODE_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_PSTDEV_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_PVARIANCE_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_STDEV_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_VARIANCE_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_QUANTILES_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_COVARIANCE_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_PEARSON_CORRELATION_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_CORRELATION_PRIVATE_RANK_DATA_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_SPEARMAN_CORRELATION_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_CORRELATION_FUNC)
__MASTER_STATISTICS_CREATE_SOMEFUNC(__MASTER_STATISTICS_CREATE_LINEAR_REGRESSION_FUNC)

#undef __MASTER_STATISTICS_CREATE_SOMEFUNC
#undef __MASTER_STATISTICS_CREATE_SUM_FUNC
#undef __MASTER_STATISTICS_CREATE_MEAN_FUNC
#undef __MASTER_STATISTICS_CREATE_FMEAN_FUNC
#undef __MASTER_STATISTICS_CREATE_GEOMETRIC_MEAN_FUNC
#undef __MASTER_STATISTICS_CREATE_HARMONIC_MEAN_FUNC
#undef __MASTER_STATISTICS_CREATE_MEDIAN_FUNC
#undef __MASTER_STATISTICS_CREATE_MEDIAN_LOW_FUNC
#undef __MASTER_STATISTICS_CREATE_MEDIAN_HIGH_FUNC
#undef __MASTER_STATISTICS_CREATE_MEDIAN_GROUPED_FUNC
#undef __MASTER_STATISTICS_CREATE_MODE_FUNC
#undef __MASTER_STATISTICS_CREATE_MULTI_MODE_FUNC
#undef __MASTER_STATISTICS_CREATE_PSTDEV_FUNC
#undef __MASTER_STATISTICS_CREATE_PVARIANCE_FUNC
#undef __MASTER_STATISTICS_CREATE_STDEV_FUNC
#undef __MASTER_STATISTICS_CREATE_VARIANCE_FUNC
#undef __MASTER_STATISTICS_CREATE_QUANTILES_FUNC
#undef __MASTER_STATISTICS_CREATE_COVARIANCE_FUNC
#undef __MASTER_STATISTICS_CREATE_PEARSON_CORRELATION_FUNC
#undef __MASTER_STATISTICS_CREATE_CORRELATION_PRIVATE_RANK_DATA_FUNC
#undef __MASTER_STATISTICS_CREATE_SPEARMAN_CORRELATION_FUNC
#undef __MASTER_STATISTICS_CREATE_CORRELATION_FUNC
#undef __MASTER_STATISTICS_CREATE_LINEAR_REGRESSION_FUNC

#endif /* __MASTER_STATISTICS_INCLUDE_H__ */

// be master~
