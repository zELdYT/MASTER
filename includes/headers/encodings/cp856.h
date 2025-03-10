
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CP856_INCLUDE_H__
#define __MASTER_CP856_INCLUDE_H__

/* #! Low priority !# */

#include "../../headers/enumeration/master_enum.h"

typedef struct {
	UI4 * symbol;
	UI8 unicode;
} MASTER_CP856_element;

const MASTER_CP856_element
MASTER_CP856_table[256] = {
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
	{ U"↕", 0xe28695 },
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
	{ U"  ", 0x2020 },
	{ U"!", 0x21 },
	{ U"\"", 0x22 },
	{ U"#", 0x23 },
	{ U"$", 0x24 },
	{ U"%", 0x25 },
	{ U"&", 0x26 },
	{ U"'", 0x27 },
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
	{ U"א", 0xd790 },
	{ U"ב", 0xd791 },
	{ U"ג", 0xd792 },
	{ U"ד", 0xd793 },
	{ U"ה", 0xd794 },
	{ U"ו", 0xd795 },
	{ U"ז", 0xd796 },
	{ U"ח", 0xd797 },
	{ U"ט", 0xd798 },
	{ U"י", 0xd799 },
	{ U"ך", 0xd79a },
	{ U"כ", 0xd79b },
	{ U"ל", 0xd79c },
	{ U"ם", 0xd79d },
	{ U"מ", 0xd79e },
	{ U"ן", 0xd79f },
	{ U"נ", 0xd7a0 },
	{ U"ס", 0xd7a1 },
	{ U"ע", 0xd7a2 },
	{ U"ף", 0xd7a3 },
	{ U"פ", 0xd7a4 },
	{ U"ץ", 0xd7a5 },
	{ U"צ", 0xd7a6 },
	{ U"ק", 0xd7a7 },
	{ U"ר", 0xd7a8 },
	{ U"ש", 0xd7a9 },
	{ U"ת", 0xd7aa },
	{ U"\0", 0x00 }, /* not used */
	{ U"£", 0xc2a3 },
	{ U"\0", 0x00 }, /* not used */
	{ U"×", 0xc397 },
	{ U"₪", 0xe282aa },
	{ U"‎", 0xe2808e },
	{ U"‏", 0xe2808f },
	{ U"‪", 0xe280aa },
	{ U"‫", 0xe280ab },
	{ U"‭", 0xe280ad },
	{ U"‮", 0xe280ae },
	{ U"‬", 0xe280ac },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"®", 0xc2ae },
	{ U"¬", 0xc2ac },
	{ U"½", 0xc2bd },
	{ U"¼", 0xc2bc },
	{ U"€", 0xe282ac },
	{ U"«", 0xc2ab },
	{ U"»", 0xc2bb },
	{ U"░", 0xe29691 },
	{ U"▒", 0xe29692 },
	{ U"▓", 0xe29693 },
	{ U"│", 0xe29482 },
	{ U"┤", 0xe294a4 },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"©", 0xc2a9 },
	{ U"╣", 0xe295a3 },
	{ U"║", 0xe29591 },
	{ U"╗", 0xe29597 },
	{ U"╝", 0xe2959d },
	{ U"¢", 0xc2a2 },
	{ U"¥", 0xc2a5 },
	{ U"┐", 0xe29490 },
	{ U"└", 0xe29494 },
	{ U"┴", 0xe294b4 },
	{ U"┬", 0xe294ac },
	{ U"├", 0xe2949c },
	{ U"─", 0xe29480 },
	{ U"┼", 0xe294bc },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"╚", 0xe2959a },
	{ U"╔", 0xe29594 },
	{ U"╩", 0xe295a9 },
	{ U"╦", 0xe295a6 },
	{ U"╠", 0xe295a0 },
	{ U"═", 0xe29590 },
	{ U"╬", 0xe295ac },
	{ U"¤", 0xc2a4 },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"┘", 0xe29498 },
	{ U"┌", 0xe2948c },
	{ U"█", 0xe29688 },
	{ U"▄", 0xe29684 },
	{ U"¦", 0xc2a6 },
	{ U"\0", 0x00 }, /* not used */
	{ U"▀", 0xe29680 },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"µ", 0xc2b5 },
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"\0", 0x00 }, /* not used */
	{ U"¯", 0xc2af },
	{ U"´", 0xc2b4 },
	{ U"­", 0xc2ad },
	{ U"±", 0xc2b1 },
	{ U"‗", 0xe28097 },
	{ U"¾", 0xc2be },
	{ U"¶", 0xc2b6 },
	{ U"§", 0xc2a7 },
	{ U"÷", 0xc3b7 },
	{ U"¸", 0xc2b8 },
	{ U"°", 0xc2b0 },
	{ U"¨", 0xc2a8 },
	{ U"·", 0xc2b7 },
	{ U"¹", 0xc2b9 },
	{ U"³", 0xc2b3 },
	{ U"²", 0xc2b2 },
	{ U"■", 0xe296a0 },
	{ U" ", 0xc2a0 }
};

#endif /* __MASTER_CP856_INCLUDE_H__ */

// be master~
