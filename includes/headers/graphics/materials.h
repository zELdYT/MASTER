
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_MATERIALS_INCLUDE_H__
#define __MASTER_MATERIALS_INCLUDE_H__

/* #! Low priority !# */

typedef struct {
	float ambient[3];
	float diffuse[3];
	float specular[3];
	float shininess;
	const char * const name;
} MASTER_material;

const MASTER_material MASTER_materials[] = {
	{ { 0.0215, 0.1745, 0.0215 }, { 0.07568, 0.61424, 0.07568 }, { 0.633, 0.727811, 0.633 }, 0.6, "Emerald" },
	{ { 0.135, 0.2225, 0.1575 }, { 0.54, 0.89, 0.63 }, { 0.316228, 0.316228, 0.316228 }, 0.1, "Jade" },
	{ { 0.05375, 0.05, 0.06625 }, { 0.18275, 0.17, 0.22525 }, { 0.332741, 0.328634, 0.346435 }, 0.3, "Obsidian" },
	{ { 0.25, 0.20725, 0.20725 }, { 1, 0.829, 0.829 }, { 0.296648, 0.296648, 0.296648 }, 0.088, "Pearl" },
	{ { 0.1745, 0.01175, 0.01175 }, { 0.61424, 0.04136, 0.04136 }, { 0.727811, 0.626959, 0.626959 }, 0.6, "Ruby" },
	{ { 0.1, 0.18725, 0.1745 }, { 0.396, 0.74151, 0.69102 }, { 0.297254, 0.30829, 0.306678 }, 0.1, "Turquoise" },
	{ { 0.329412, 0.223529, 0.027451 }, { 0.780392, 0.568627, 0.113725 }, { 0.992157, 0.941176, 0.807843 }, 0.21794872, "Brass" },
	{ { 0.2125, 0.1275, 0.054 }, { 0.714, 0.4284, 0.18144 }, { 0.393548, 0.271906, 0.166721 }, 0.2, "Bronze" },
	{ { 0.25, 0.25, 0.25 }, { 0.4, 0.4, 0.4 }, { 0.774597, 0.774597, 0.774597 }, 0.6, "Chrome" },
	{ { 0.19125, 0.0735, 0.0225 }, { 0.7038, 0.27048, 0.0828 }, { 0.256777, 0.137622, 0.086014 }, 0.1, "Copper" },
	{ { 0.24725, 0.1995, 0.0745 }, { 0.75164, 0.60648, 0.22648 }, { 0.628281, 0.555802, 0.366065 }, 0.4, "Gold" },
	{ { 0.19225, 0.19225, 0.19225 }, { 0.50754, 0.50754, 0.50754 }, { 0.508273, 0.508273, 0.508273 }, 0.4, "Silver" },
	{ { 0, 0, 0 }, { 0.01, 0.01, 0.01 }, { 0.50, 0.50, 0.50 }, 0.25, "Black plastic" },
	{ { 0, 0.1, 0.06 }, { 0, 0.50980392, 0.50980392 }, { 0.50196078, 0.50196078, 0.50196078 }, 0.25, "Cyan plastic" },
	{ { 0, 0, 0 }, { 0.1, 0.35, 0.1 }, { 0.45, 0.55, 0.45 }, 0.25, "Green plastic" },
	{ { 0, 0, 0 }, { 0.5, 0, 0 }, { 0.7, 0.6, 0.6 }, 0.25, "Red plastic" },  { { 0, 0, 0 }, { 0.55, 0.55, 0.55 }, { 0.70, 0.70, 0.70 }, 0.25, "White plastic" },
	{ { 0, 0, 0 }, { 0.5, 0.5, 0 }, { 0.60, 0.60, 0.50 }, 0.25, "Yellow plastic" },
	{ { 0.02, 0.02, 0.02 }, { 0.01, 0.01, 0.01 }, { 0.4, 0.4, 0.4 }, 0.078125, "Black rubber" },
	{ { 0, 0.05, 0.05 }, { 0.4, 0.5, 0.5 }, { 0.04, 0.7, 0.7 }, 0.078125, "Cyan rubber" },
	{ { 0, 0.05, 0 }, { 0.4, 0.5, 0.4 }, { 0.04, 0.7, 0.04 }, 0.078125, "Green rubber" },
	{ { 0.05, 0, 0 }, { 0.5, 0.4, 0.4 }, { 0.7, 0.04, 0.04 }, 0.078125, "Red rubber" },
	{ { 0.05, 0.05, 0.05 }, { 0.5, 0.5, 0.5 }, { 0.7, 0.7, 0.7 }, 0.078125, "White rubber" },
	{ { 0.05, 0.05, 0 }, { 0.5, 0.5, 0.4 }, { 0.7, 0.7, 0.04 }, 0.078125, "Yellow rubber" }
};

#endif /* __MASTER_MATERIALS_INCLUDE_H__ */

// be master~
