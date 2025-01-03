
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CP777_INCLUDE_H__
#define __MASTER_CP777_INCLUDE_H__

/* #! Low priority !# */

#include "../../headers/enumeration/master_enum.h"

typedef struct {
	UI4 * symbol;
	UI8 unicode;
} MASTER_CP777_element;

const MASTER_CP777_element
MASTER_CP777_table[256] = {
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
	{ U"Á", 0xc381 },
	{ U"ü", 0xc3bc },
	{ U"é", 0xc3a9 },
	{ U"à", 0xc3a0 },
	{ U"ä", 0xc3a4 },
	{ U"ẽ", 0xe1babd },
	{ U"ã", 0xc3a3 },
	{ U"á", 0xc3a1 },
	{ U"ù", 0xc3b9 },
	{ U"ą́", 0xc485cc81 },
	{ U"Ė̃", 0xc496cc83 },
	{ U"ė̃", 0xc497cc83 },
	{ U"i̇́", 0x69cc87cc81 },
	{ U"È", 0xc388 },
	{ U"Ä", 0xc384 },
	{ U"Ã", 0xc383 },
	{ U"É", 0xc389 },
	{ U"ū́", 0xc5abcc81 },
	{ U"Ū́", 0xc5aacc81 },
	{ U"ý", 0xc3bd },
	{ U"ö", 0xc3b6 },
	{ U"Ẽ", 0xe1babc },
	{ U"Ę́", 0xc498cc81 },
	{ U"Ú", 0xc39a },
	{ U"ú", 0xc3ba },
	{ U"Ö", 0xc396 },
	{ U"Ü", 0xc39c },
	{ U"ė́", 0xc497cc81 },
	{ U"Ę̃", 0xc498cc83 },
	{ U"Ė́", 0xc496cc81 },
	{ U"Ũ", 0xc5a8 },
	{ U"i̇̃", 0x69cc87cc83 },
	{ U"À", 0xc380 },
	{ U"Í", 0xc38d },
	{ U"ó", 0xc3b3 },
	{ U"Ỹ", 0xe1bbb8 },
	{ U"ỹ", 0xe1bbb9 },
	{ U"è", 0xc3a8 },
	{ U"L̃", 0x4ccc83 },
	{ U"M̃", 0x4dcc83 },
	{ U"Ñ", 0xc391 },
	{ U"Ū̃", 0xc5aacc83 },
	{ U"Ų́", 0xc5b2cc81 },
	{ U"Ų̃", 0xc5b2cc83 },
	{ U"ų́", 0xc5b3cc81 },
	{ U"Ù", 0xc399 },
	{ U"R̃", 0x52cc83 },
	{ U"r̃", 0x72cc83 },
	{ U"░", 0xe29691 },
	{ U"▒", 0xe29692 },
	{ U"▓", 0xe29693 },
	{ U"│", 0xe29482 },
	{ U"ɑ", 0xc991 },
	{ U"ą̃", 0xc485cc83 },
	{ U"ʌ", 0xca8c },
	{ U"“", 0xe2809c },
	{ U"ū̃", 0xc5abcc83 },
	{ U"ɔ", 0xc994 },
	{ U"║", 0xe29591 },
	{ U"╗", 0xe29597 },
	{ U"╝", 0xe2959d },
	{ U"Ą̃", 0xc484cc83 },
	{ U"m̃", 0x6dcc83 },
	{ U"┐", 0xe29490 },
	{ U"└", 0xe29494 },
	{ U"ə", 0xc999 },
	{ U"ɜ", 0xc99c },
	{ U"ɡ", 0xc9a1 },
	{ U"─", 0xe29480 },
	{ U"ɪ", 0xc9aa },
	{ U"ũ", 0xc5a9 },
	{ U"ʒ", 0xca92 },
	{ U"╚", 0xe2959a },
	{ U"╔", 0xe29594 },
	{ U"ŋ", 0xc58b },
	{ U"θ", 0xceb8 },
	{ U"ʃ", 0xca83 },
	{ U"═", 0xe29590 },
	{ U"ʊ", 0xca8a },
	{ U"ˈ", 0xcb88 },
	{ U"Ĩ", 0xc4a8 },
	{ U"ˌ", 0xcb8c },
	{ U"æ", 0xc3a6 },
	{ U"ð", 0xc3b0 },
	{ U"ñ", 0xc3b1 },
	{ U"„", 0xe2809e },
	{ U"ę̃", 0xc499cc83 },
	{ U"­", 0xc2ad },
	{ U"ę́", 0xc499cc81 },
	{ U"┘", 0xe29498 },
	{ U"┌", 0xe2948c },
	{ U"█", 0xe29688 },
	{ U"Ą", 0xc484 },
	{ U"ą", 0xc485 },
	{ U"Č", 0xc48c },
	{ U"č", 0xc48d },
	{ U"Ó", 0xc393 },
	{ U"ß", 0xc39f },
	{ U"Ý", 0xc39d },
	{ U"Į̃", 0xc4aecc83 },
	{ U"õ", 0xc3b5 },
	{ U"Õ", 0xc395 },
	{ U"l̃", 0x6ccc83 },
	{ U"į̇̃", 0xc4afcc87cc83 },
	{ U"Ì", 0xc38c },
	{ U"i̇̀", 0x69cc87cc80 },
	{ U"Į́", 0xc4aecc81 },
	{ U"į̇́", 0xc4afcc87cc81 },
	{ U"ò", 0xc3b2 },
	{ U"Ą́", 0xc484cc81 },
	{ U"Ò", 0xc392 },
	{ U"ų̃", 0xc5b3cc83 },
	{ U"Ę", 0xc498 },
	{ U"ę", 0xc499 },
	{ U"Ė", 0xc496 },
	{ U"ė", 0xc497 },
	{ U"Į", 0xc4ae },
	{ U"į", 0xc4af },
	{ U"Š", 0xc5a0 },
	{ U"š", 0xc5a1 },
	{ U"Ų", 0xc5b2 },
	{ U"ų", 0xc5b3 },
	{ U"Ū", 0xc5aa },
	{ U"ū", 0xc5ab },
	{ U"Ž", 0xc5bd },
	{ U"ž", 0xc5be },
	{ U"■", 0xe296a0 },
	{ U" ", 0xc2a0 }
};

#endif /* __MASTER_CP777_INCLUDE_H__ */

// be master~
