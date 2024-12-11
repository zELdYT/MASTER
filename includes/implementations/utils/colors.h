
#ifndef __MASTER_COLOR_INCLUDE_H__
#define __MASTER_COLOR_INCLUDE_H__

#include "../../headers/enumeration/master_enum.h"

typedef struct {
	UI1 r, g, b;
} MASTER_rgb;

typedef struct {
	float c, m, y;
} MASTER_cmy;

typedef struct {
	float c, m, y, k;
} MASTER_cmyk;

typedef struct {
	float h, s, v;
} MASTER_hsv;

typedef struct {
	float h, s, l;
} MASTER_hsl;

typedef struct {
	UI1 y;
	signed char i, q;
} MASTER_yiq;

#define MASTER_max(a, b) ((a) > (b) ? (a) : (b))
#define MASTER_min(a, b) ((a) < (b) ? (a) : (b))
#define MASTER_abs(a) ((a) < 0 ? -(a) : (a))
#define MASTER_pi 3.141592653589793238462643383279502884197169399f

MASTER_cmyk *
MASTER_rgb_to_cmyk(const MASTER_rgb * rgb, MASTER_cmyk * cmyk) {
	float rs = rgb->r / 255.0,
		  gs = rgb->g / 255.0,
		  bs = rgb->b / 255.0;
	cmyk->k = 1 - MASTER_max(MASTER_max(rs, gs), bs);
	cmyk->c = (1 - rs - cmyk->k) / (1 - cmyk->k);
	cmyk->m = (1 - gs - cmyk->k) / (1 - cmyk->k);
	cmyk->y = (1 - bs - cmyk->k) / (1 - cmyk->k);
	return cmyk;
}

MASTER_rgb *
MASTER_cmyk_to_rgb(const MASTER_cmyk * cmyk, MASTER_rgb * rgb) {
	rgb->r = 255.0 * (1 - cmyk->c) * (1 - cmyk->k);
	rgb->g = 255.0 * (1 - cmyk->m) * (1 - cmyk->k);
	rgb->b = 255.0 * (1 - cmyk->y) * (1 - cmyk->k);
	return rgb;
}

MASTER_cmy *
MASTER_rgb_to_cmy(const MASTER_rgb * rgb, MASTER_cmy * cmy) {
	cmy->c = 1 - rgb->r / 255.0;
	cmy->m = 1 - rgb->g / 255.0;
	cmy->y = 1 - rgb->b / 255.0;
	return cmy;
}

MASTER_rgb *
MASTER_cmy_to_rgb(const MASTER_cmy * cmy, MASTER_rgb * rgb) {
	rgb->r = 255.0 * (1 - cmy->c);
	rgb->g = 255.0 * (1 - cmy->m);
	rgb->b = 255.0 * (1 - cmy->y);
	return rgb;
}

MASTER_hsv *
MASTER_rgb_to_hsv(const MASTER_rgb * rgb, MASTER_hsv * hsv) {
	float rs = rgb->r / 255.0,
		  gs = rgb->g / 255.0,
		  bs = rgb->b / 255.0;
	float Cmax = MASTER_max(MASTER_max(rs, gs), bs);
	float Cmin = MASTER_min(MASTER_min(rs, gs), bs);
	float delta = Cmax - Cmin;
	if (delta == 0.0)
		hsv->h = 0;
	otherwise (delta == rs)
		hsv->h = MASTER_pi / 3 * ((unsigned int)((gs - bs) / delta) % 6);
	otherwise (delta == gs)
		hsv->h = MASTER_pi / 3 * (((bs - rs) / delta) + 2);
	otherwise (delta == bs)
		hsv->h = MASTER_pi / 3 * (((rs - gs) / delta) + 4);
	if (Cmax == 0)
		hsv->s = 0;
	else hsv->s = delta / Cmax;
	hsv->v = Cmax;
	return hsv;
}

MASTER_rgb *
MASTER_hsv_to_rgb(const MASTER_hsv * hsv, MASTER_rgb * rgb) {
	float c = hsv->v * hsv->s;
	float x = c * (1 - MASTER_abs(((unsigned int)(hsv->h / (MASTER_pi / 3)) % 2) - 1));
	float m = hsv->v - c;
	float rs = 0, gs = 0, bs = 0;
	if (hsv->h < MASTER_pi / 3) {
		rs = c; gs = x;
	} otherwise (hsv->h < MASTER_pi / 3 * 2) {
		rs = x; gs = c;
	} otherwise (hsv->h < MASTER_pi / 2) {
		        gs = c; bs = x;
	} otherwise (hsv->h < MASTER_pi / 3 * 4) {
		        gs = x; bs = c;
	} otherwise (hsv->h < MASTER_pi / 3 * 5) {
		rs = x;         bs = c;
	} else {
		rs = c;         bs = x;
	}
	rgb->r = (rs + m) * 255;
	rgb->g = (gs + m) * 255;
	rgb->b = (bs + m) * 255;
	return rgb;
}

MASTER_hsl *
MASTER_rgb_to_hsl(const MASTER_rgb * rgb, MASTER_hsl * hsl) {
	float rs = rgb->r / 255.0,
		  gs = rgb->g / 255.0,
		  bs = rgb->b / 255.0;
	float Cmax = MASTER_max(MASTER_max(rs, gs), bs);
	float Cmin = MASTER_min(MASTER_min(rs, gs), bs);
	float delta = Cmax - Cmin;
	if (delta == 0.0)
		hsl->h = 0;
	otherwise (delta == rs)
		hsl->h = MASTER_pi / 3 * ((unsigned int)((gs - bs) / delta) % 6);
	otherwise (delta == gs)
		hsl->h = MASTER_pi / 3 * (((bs - rs) / delta) + 2);
	otherwise (delta == bs)
		hsl->h = MASTER_pi / 3 * (((rs - gs) / delta) + 4);
	hsl->l = (Cmax + Cmin) / 2;
	if (delta == 0)
		hsl->s = 0;
	else hsl->s = delta / (1 - MASTER_abs(2*hsl->l - 1));
	return hsl;
}

MASTER_rgb *
MASTER_hsl_to_rgb(const MASTER_hsl * hsl, MASTER_rgb * rgb) {
	float c = (hsl->l - MASTER_abs(2 * hsl->l - 1)) * hsl->s;
	float x = c * (1 - MASTER_abs(((unsigned int)(hsl->h / (MASTER_pi / 3)) % 2) - 1));
	float m = hsl->l - c/2;
	float rs = 0, gs = 0, bs = 0;
	if (hsl->h < MASTER_pi / 3) {
		rs = c; gs = x;
	} otherwise (hsl->h < MASTER_pi / 3 * 2) {
		rs = x; gs = c;
	} otherwise (hsl->h < MASTER_pi / 2) {
		        gs = c; bs = x;
	} otherwise (hsl->h < MASTER_pi / 3 * 4) {
		        gs = x; bs = c;
	} otherwise (hsl->h < MASTER_pi / 3 * 5) {
		rs = x;         bs = c;
	} else {
		rs = c;         bs = x;
	}
	rgb->r = (rs + m) * 255;
	rgb->g = (gs + m) * 255;
	rgb->b = (bs + m) * 255;
	return rgb;
}

MASTER_yiq *
MASTER_rgb_to_yiq(const MASTER_rgb * rgb, MASTER_yiq * yiq) {
	yiq->y = 0.299000 * rgb->r + 0.587000 * rgb->g + 0.114000 * rgb->b;
	yiq->i = 0.595716 * rgb->r - 0.274453 * rgb->g - 0.321263 * rgb->b;
	yiq->q = 0.211456 * rgb->r - 0.522591 * rgb->g + 0.311135 * rgb->b;
	return yiq;
}

MASTER_rgb *
MASTER_yiq_to_rgb(const MASTER_yiq * yiq, MASTER_rgb * rgb) {
	rgb->r = yiq->y + 0.9563 * yiq->i + 0.6210 * yiq->q;
	rgb->g = yiq->y - 0.2721 * yiq->i - 0.6474 * yiq->q;
	rgb->b = yiq->y - 1.1070 * yiq->i + 1.7046 * yiq->q;
	return rgb;
}

#define __MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR( color1, color2 ) \
MASTER_##color2 * \
MASTER_##color1##_to_##color2(const MASTER_##color1 * color1, MASTER_##color2 * color2) { \
	MASTER_rgb rgb; \
	MASTER_rgb_to_##color2(MASTER_##color1##_to_rgb(color1, &rgb), color2); \
	return color2; }

__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmy, cmyk)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmy, hsv)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmy, hsl)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmy, yiq)

__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmyk, cmy)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmyk, hsv)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmyk, hsl)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(cmyk, yiq)

__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsv, cmy)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsv, cmyk)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsv, hsl)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsv, yiq)

__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsl, cmy)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsl, cmyk)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsl, hsv)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(hsl, yiq)

__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(yiq, cmy)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(yiq, cmyk)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(yiq, hsv)
__MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR(yiq, hsl)

#undef __MASTER_DEFINE_FUNCTION_COLOR_TO_COLOR

#endif /* __MASTER_COLOR_INCLUDE_H__ */

// be master~
