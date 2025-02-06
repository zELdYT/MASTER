
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CP737_INCLUDE_H__
#define __MASTER_CP737_INCLUDE_H__

/* #! Low priority !# */

#include "../../headers/enumeration/master_enum.h"

typedef struct {
	UI4 * symbol;
	UI8 unicode;
} MASTER_cp737_element;

const MASTER_cp737_element
MASTER_cp737_table[256] = {
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
	{ U"Α", 0xce91 },
	{ U"Β", 0xce92 },
	{ U"Γ", 0xce93 },
	{ U"Δ", 0xce94 },
	{ U"Ε", 0xce95 },
	{ U"Ζ", 0xce96 },
	{ U"Η", 0xce97 },
	{ U"Θ", 0xce98 },
	{ U"Ι", 0xce99 },
	{ U"Κ", 0xce9a },
	{ U"Λ", 0xce9b },
	{ U"Μ", 0xce9c },
	{ U"Ν", 0xce9d },
	{ U"Ξ", 0xce9e },
	{ U"Ο", 0xce9f },
	{ U"Π", 0xcea0 },
	{ U"Ρ", 0xcea1 },
	{ U"Σ", 0xcea3 },
	{ U"Τ", 0xcea4 },
	{ U"Υ", 0xcea5 },
	{ U"Φ", 0xcea6 },
	{ U"Χ", 0xcea7 },
	{ U"Ψ", 0xcea8 },
	{ U"Ω", 0xcea9 },
	{ U"α", 0xceb1 },
	{ U"β", 0xceb2 },
	{ U"γ", 0xceb3 },
	{ U"δ", 0xceb4 },
	{ U"ε", 0xceb5 },
	{ U"ζ", 0xceb6 },
	{ U"η", 0xceb7 },
	{ U"θ", 0xceb8 },
	{ U"ι", 0xceb9 },
	{ U"κ", 0xceba },
	{ U"λ", 0xcebb },
	{ U"μ", 0xcebc },
	{ U"ν", 0xcebd },
	{ U"ξ", 0xcebe },
	{ U"ο", 0xcebf },
	{ U"π", 0xcf80 },
	{ U"ρ", 0xcf81 },
	{ U"σ", 0xcf83 },
	{ U"ς", 0xcf82 },
	{ U"τ", 0xcf84 },
	{ U"υ", 0xcf85 },
	{ U"φ", 0xcf86 },
	{ U"χ", 0xcf87 },
	{ U"ψ", 0xcf88 },
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
	{ U"ω", 0xcf89 },
	{ U"ά", 0xceac },
	{ U"έ", 0xcead },
	{ U"ή", 0xceae },
	{ U"ϊ", 0xcf8a },
	{ U"ί", 0xceaf },
	{ U"ό", 0xcf8c },
	{ U"ύ", 0xcf8d },
	{ U"ϋ", 0xcf8b },
	{ U"ώ", 0xcf8e },
	{ U"Ά", 0xce86 },
	{ U"Έ", 0xce88 },
	{ U"Ή", 0xce89 },
	{ U"Ί", 0xce8a },
	{ U"Ό", 0xce8c },
	{ U"Ύ", 0xce8e },
	{ U"Ώ", 0xce8f },
	{ U"±", 0xc2b1 },
	{ U"≥", 0xe289a5 },
	{ U"≤", 0xe289a4 },
	{ U"Ϊ", 0xceaa },
	{ U"Ϋ", 0xceab },
	{ U"÷", 0xc3b7 },
	{ U"≈", 0xe28988 },
	{ U"°", 0xc2b0 },
	{ U"∙", 0xe28899 },
	{ U"·", 0xc2b7 },
	{ U"√", 0xe2889a },
	{ U"ⁿ", 0xe281bf },
	{ U"²", 0xc2b2 },
	{ U"■", 0xe296a0 },
	{ U" ", 0xc2a0 }
};

#endif /* __MASTER_CP737_INCLUDE_H__ */

// be master~
