
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CP720_INCLUDE_H__
#define __MASTER_CP720_INCLUDE_H__

/* #! Low priority !# */

#include "../../headers/enumeration/master_enum.h"

typedef struct {
	UI4 * symbol;
	UI8 unicode;
} MASTER_cp720_element;

const MASTER_cp720_element
MASTER_cp720_table[256] = {
	{ U"\0", 0x00 },
	{ U"☺", 0xe298ba },
	{ U"☻", 0xe298bb },
	{ U"♥", 0xe299a5 },
	{ U"♦", 0xe299a6 },
	{ U"♣", 0xe299a3 },
	{ U"♠", 0xe299a0 },
	{ U"•", 0xe280a2 },
	{ U"◘", 0xe29798 },
	{ U"○", 0xe2978b },
	{ U"◙", 0xe29799 },
	{ U"♂", 0xe29982 },
	{ U"♀", 0xe29980 },
	{ U"♪", 0xe299aa },
	{ U"♫", 0xe299ab },
	{ U"☼", 0xe298bc },
	{ U"►", 0xe296ba },
	{ U"◄", 0xe29784 },
	{ U"↕︎", 0xe28695efb88e },
	{ U"‼", 0xe280bc },
	{ U"¶", 0xc2b6 },
	{ U"§", 0xc2a7 },
	{ U"▬", 0xe296ac },
	{ U"↨", 0xe286a8 },
	{ U"↑", 0xe28691 },
	{ U"↓", 0xe28693 },
	{ U"→", 0xe28692 },
	{ U"←", 0xe28690 },
	{ U"∟", 0xe2889f },
	{ U"↔", 0xe28694 },
	{ U"▲", 0xe296b2 },
	{ U"▼", 0xe296bc },
	{ U" ", 0x20 },
	{ U"!", 0x21 },
	{ U"\"", 0x22 },
	{ U"#", 0x23 },
	{ U"$", 0x24 },
	{ U"%", 0x25 },
	{ U"&", 0x26 },
	{ U"\'", 0x27 },
	{ U"(", 0x28 },
	{ U")", 0x29 },
	{ U"*", 0x2a },
	{ U"+", 0x2b },
	{ U",", 0x2c },
	{ U"-", 0x2d },
	{ U".", 0x2e },
	{ U"/", 0x2f },
	{ U"0", 0x30 },
	{ U"1", 0x31 },
	{ U"2", 0x32 },
	{ U"3", 0x33 },
	{ U"4", 0x34 },
	{ U"5", 0x35 },
	{ U"6", 0x36 },
	{ U"7", 0x37 },
	{ U"8", 0x38 },
	{ U"9", 0x39 },
	{ U":", 0x3a },
	{ U";", 0x3b },
	{ U"<", 0x3c },
	{ U"=", 0x3d },
	{ U">", 0x3e },
	{ U"?", 0x3f },
	{ U"@", 0x40 },
	{ U"A", 0x41 },
	{ U"B", 0x42 },
	{ U"C", 0x43 },
	{ U"D", 0x44 },
	{ U"E", 0x45 },
	{ U"F", 0x46 },
	{ U"G", 0x47 },
	{ U"H", 0x48 },
	{ U"I", 0x49 },
	{ U"J", 0x4a },
	{ U"K", 0x4b },
	{ U"L", 0x4c },
	{ U"M", 0x4d },
	{ U"N", 0x4e },
	{ U"O", 0x4f },
	{ U"P", 0x50 },
	{ U"Q", 0x51 },
	{ U"R", 0x52 },
	{ U"S", 0x53 },
	{ U"T", 0x54 },
	{ U"U", 0x55 },
	{ U"V", 0x56 },
	{ U"W", 0x57 },
	{ U"X", 0x58 },
	{ U"Y", 0x59 },
	{ U"Z", 0x5a },
	{ U"[", 0x5b },
	{ U"\\", 0x5c },
	{ U"]", 0x5d },
	{ U"^", 0x5e },
	{ U"_", 0x5f },
	{ U"`", 0x60 },
	{ U"a", 0x61 },
	{ U"b", 0x62 },
	{ U"c", 0x63 },
	{ U"d", 0x64 },
	{ U"e", 0x65 },
	{ U"f", 0x66 },
	{ U"g", 0x67 },
	{ U"h", 0x68 },
	{ U"i", 0x69 },
	{ U"j", 0x6a },
	{ U"k", 0x6b },
	{ U"l", 0x6c },
	{ U"m", 0x6d },
	{ U"n", 0x6e },
	{ U"o", 0x6f },
	{ U"p", 0x70 },
	{ U"q", 0x71 },
	{ U"r", 0x72 },
	{ U"s", 0x73 },
	{ U"t", 0x74 },
	{ U"u", 0x75 },
	{ U"v", 0x76 },
	{ U"w", 0x77 },
	{ U"x", 0x78 },
	{ U"y", 0x79 },
	{ U"z", 0x7a },
	{ U"{", 0x7b },
	{ U"|", 0x7c },
	{ U"}", 0x7d },
	{ U"~", 0x7e },
	{ U"⌂", 0xe28c82 },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"é", 0xc3a9 },
	{ U"â", 0xc3a2 },
	{ U"\0", 0x00 }, /* not used */
	{ U"à", 0xc3a0 },
	{ U"\0", 0x00 }, /* not used */
	{ U"ç", 0xc3a7 },
	{ U"ê", 0xc3aa },
	{ U"ë", 0xc3ab },
	{ U"è", 0xc3a8 },
	{ U"ï", 0xc3af },
	{ U"î", 0xc3ae },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"_ّ", 0x5fd991 },
	{ U"_ْ", 0x5fd992 },
	{ U"ô", 0xc3b4 },
	{ U"¤", 0xc2a4 },
	{ U"ـ", 0xd980 },
	{ U"û", 0xc3bb },
	{ U"ù", 0xc3b9 },
	{ U"ء", 0xd8a1 },
	{ U"آ", 0xd8a2 },
	{ U"أ", 0xd8a3 },
	{ U"ؤ", 0xd8a4 },
	{ U"£", 0xc2a3 },
	{ U"إ", 0xd8a5 },
	{ U"ئ", 0xd8a6 },
	{ U"ا", 0xd8a7 },
	{ U"ب", 0xd8a8 },
	{ U"ة", 0xd8a9 },
	{ U"ت", 0xd8aa },
	{ U"ث", 0xd8ab },
	{ U"ج", 0xd8ac },
	{ U"ح", 0xd8ad },
	{ U"خ", 0xd8ae },
	{ U"د", 0xd8af },
	{ U"ذ", 0xd8b0 },
	{ U"ر", 0xd8b1 },
	{ U"ز", 0xd8b2 },
	{ U"س", 0xd8b3 },
	{ U"ش", 0xd8b4 },
	{ U"ص", 0xd8b5 },
	{ U"«", 0xc2ab },
	{ U"»", 0xc2bb },
	{ U"░", 0xe29691 },
	{ U"▒", 0xe29692 },
	{ U"▓", 0xe29693 },
	{ U"│", 0xe29482 },
	{ U"┤", 0xe294a4 },
	{ U"╡", 0xe295a1 },
	{ U"╢", 0xe295a2 },
	{ U"╖", 0xe29596 },
	{ U"╕", 0xe29595 },
	{ U"╣", 0xe295a3 },
	{ U"║", 0xe29591 },
	{ U"╗", 0xe29597 },
	{ U"╝", 0xe2959d },
	{ U"╜", 0xe2959c },
	{ U"╛", 0xe2959b },
	{ U"┐", 0xe29490 },
	{ U"└", 0xe29494 },
	{ U"┴", 0xe294b4 },
	{ U"┬", 0xe294ac },
	{ U"├", 0xe2949c },
	{ U"─", 0xe29480 },
	{ U"┼", 0xe294bc },
	{ U"╞", 0xe2959e },
	{ U"╟", 0xe2959f },
	{ U"╚", 0xe2959a },
	{ U"╔", 0xe29594 },
	{ U"╩", 0xe295a9 },
	{ U"╦", 0xe295a6 },
	{ U"╠", 0xe295a0 },
	{ U"═", 0xe29590 },
	{ U"╬", 0xe295ac },
	{ U"╧", 0xe295a7 },
	{ U"╨", 0xe295a8 },
	{ U"╤", 0xe295a4 },
	{ U"╥", 0xe295a5 },
	{ U"╙", 0xe29599 },
	{ U"╘", 0xe29598 },
	{ U"╒", 0xe29592 },
	{ U"╓", 0xe29593 },
	{ U"╫", 0xe295ab },
	{ U"╪", 0xe295aa },
	{ U"┘", 0xe29498 },
	{ U"┌", 0xe2948c },
	{ U"█", 0xe29688 },
	{ U"▄", 0xe29684 },
	{ U"▌", 0xe2968c },
	{ U"▐", 0xe29690 },
	{ U"▀", 0xe29680 },
	{ U"ض", 0xd8b6 },
	{ U"ط", 0xd8b7 },
	{ U"ظ", 0xd8b8 },
	{ U"ع", 0xd8b9 },
	{ U"غ", 0xd8ba },
	{ U"ف", 0xd981 },
	{ U"µ", 0xc2b5 },
	{ U"ق", 0xd982 },
	{ U"ك", 0xd983 },
	{ U"ل", 0xd984 },
	{ U"م", 0xd985 },
	{ U"ن", 0xd986 },
	{ U"ه", 0xd987 },
	{ U"و", 0xd988 },
	{ U"ى", 0xd989 },
	{ U"ي", 0xd98a },
	{ U"≡", 0xe289a1 },
	{ U"_ً", 0x5fd98b },
	{ U"_ٌ", 0x5fd98c },
	{ U"_ٍ", 0x5fd98d },
	{ U"_َ", 0x5fd98e },
	{ U"_ُ", 0x5fd98f },
	{ U"_ِ", 0x5fd990 },
	{ U"≈", 0xe28988 },
	{ U"°", 0xc2b0 },
	{ U"∙", 0xe28899 },
	{ U"·", 0xc2b7 },
	{ U"√", 0xe2889a },
	{ U"ⁿ", 0xe281bf },
	{ U"²", 0xc2b2 },
	{ U"■", 0xe296a0 },
	{ U" ", 0xc2a0 },
};

#endif /* __MASTER_CP720_INCLUDE_H__ */

// be master~
