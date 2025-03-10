
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CP773_INCLUDE_H__
#define __MASTER_CP773_INCLUDE_H__

/* #! Low priority !# */

#include "../../headers/enumeration/master_enum.h"

typedef struct {
	UI4 * symbol;
	UI8 unicode;
} MASTER_cp773_element;

const MASTER_cp773_element
MASTER_cp773_table[256] = {
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
	{ U"Ć", 0xc486 },
	{ U"ü", 0xc3bc },
	{ U"é", 0xc3a9 },
	{ U"ā", 0xc481 },
	{ U"ä", 0xc3a4 },
	{ U"ģ", 0xc4a3 },
	{ U"å", 0xc3a5 },
	{ U"ć", 0xc487 },
	{ U"ł", 0xc582 },
	{ U"ē", 0xc493 },
	{ U"Ŗ", 0xc596 },
	{ U"ŗ", 0xc597 },
	{ U"ī", 0xc4ab },
	{ U"Ź", 0xc5b9 },
	{ U"Ä", 0xc384 },
	{ U"Å", 0xc385 },
	{ U"É", 0xc389 },
	{ U"æ", 0xc3a6 },
	{ U"Æ", 0xc386 },
	{ U"ō", 0xc58d },
	{ U"ö", 0xc3b6 },
	{ U"Ģ", 0xc4a2 },
	{ U"¢", 0xc2a2 },
	{ U"Ś", 0xc59a },
	{ U"ś", 0xc59b },
	{ U"Ö", 0xc396 },
	{ U"Ü", 0xc39c },
	{ U"ø", 0xc3b8 },
	{ U"£", 0xc2a3 },
	{ U"Ø", 0xc398 },
	{ U"×", 0xc397 },
	{ U"¤", 0xc2a4 },
	{ U"Ā", 0xc480 },
	{ U"Ī", 0xc4aa },
	{ U"ó", 0xc3b3 },
	{ U"Ż", 0xc5bb },
	{ U"ż", 0xc5bc },
	{ U"ź", 0xc5ba },
	{ U"”", 0xe2809d },
	{ U"¦", 0xc2a6 },
	{ U"©", 0xc2a9 },
	{ U"®", 0xc2ae },
	{ U"¬", 0xc2ac },
	{ U"½", 0xc2bd },
	{ U"¼", 0xc2bc },
	{ U"Ł", 0xc581 },
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
	{ U"Ą", 0xc484 },
	{ U"ą", 0xc485 },
	{ U"Č", 0xc48c },
	{ U"č", 0xc48d },
	{ U"Ó", 0xc393 },
	{ U"ß", 0xc39f },
	{ U"Ō", 0xc58c },
	{ U"Ń", 0xc583 },
	{ U"õ", 0xc3b5 },
	{ U"Õ", 0xc395 },
	{ U"µ", 0xc2b5 },
	{ U"ń", 0xc584 },
	{ U"Ķ", 0xc4b6 },
	{ U"ķ", 0xc4b7 },
	{ U"Ļ", 0xc4bb },
	{ U"ļ", 0xc4bc },
	{ U"ņ", 0xc586 },
	{ U"Ē", 0xc492 },
	{ U"Ņ", 0xc585 },
	{ U"’", 0xe28099 },
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

#endif /* __MASTER_CP773_INCLUDE_H__ */

// be master~
