
/*
 * Copyright (c) 2024 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_LCG_ENUMERATION_INCLUDE_H__
#define __MASTER_LCG_ENUMERATION_INCLUDE_H__

#define MASTER_random_LCG_ZX81_m                   0x10001
#define MASTER_random_LCG_ZX81_a                   75
#define MASTER_random_LCG_ZX81_c                   74
#define MASTER_random_LCG_randq1_m                 0x100000000
#define MASTER_random_LCG_randq1_a                 1664525
#define MASTER_random_LCG_randq1_c                 1013904223
#define MASTER_random_LCG_borland_c_cpp_m          0x80000000
#define MASTER_random_LCG_borland_c_cpp_a          22695477
#define MASTER_random_LCG_borland_c_cpp_c          1
#define MASTER_random_LCG_glibc_m                  0x80000000
#define MASTER_random_LCG_glibc_a                  1103515245
#define MASTER_random_LCG_glibc_c                  12345
#define MASTER_random_LCG_ANSI_c_m                 0x80000000
#define MASTER_random_LCG_ANSI_c_a                 1103515245
#define MASTER_random_LCG_ANSI_c_c                 12345
#define MASTER_random_LCG_borland_delphi_m         0x100000000
#define MASTER_random_LCG_borland_delphi_a         134775813
#define MASTER_random_LCG_borland_delphi_c         1
#define MASTER_random_LCG_turbo_pascal_m           0x100000000
#define MASTER_random_LCG_turbo_pascal_a           134775813
#define MASTER_random_LCG_turbo_pascal_c           1
#define MASTER_random_LCG_microsoft_visual_c_cpp_m 0x100000000
#define MASTER_random_LCG_microsoft_visual_c_cpp_a 214013
#define MASTER_random_LCG_microsoft_visual_c_cpp_c 2531011
#define MASTER_random_LCG_microsoft_visual_basic_m 0x1000000
#define MASTER_random_LCG_microsoft_visual_basic_a 16598013
#define MASTER_random_LCG_microsoft_visual_basic_c 12820163
#define MASTER_random_LCG_native_api_m             0x7FFFFFFF
#define MASTER_random_LCG_native_api_a             0x7FFFFFED
#define MASTER_random_LCG_native_api_c             0x7FFFFFC3
#define MASTER_random_LCG_minstd_rand0_m           0x7FFFFFFF
#define MASTER_random_LCG_minstd_rand0_a           16807
#define MASTER_random_LCG_minstd_rand0_c           0
#define MASTER_random_LCG_minstd_rand_m            0x7FFFFFFF
#define MASTER_random_LCG_minstd_rand_a            48271
#define MASTER_random_LCG_minstd_rand_c            0
#define MASTER_random_LCG_MMIX_m                   0 // 2^64 overflow
#define MASTER_random_LCG_MMIX_a                   6364136223846793005
#define MASTER_random_LCG_MMIX_c                   1442695040888963407
#define MASTER_random_LCG_newlib_m                 0x8000000000000000
#define MASTER_random_LCG_newlib_a                 6364136223846793005
#define MASTER_random_LCG_newlib_c                 1
#define MASTER_random_LCG_musl_m                   0 // 2^64 overflow
#define MASTER_random_LCG_musl_a                   6364136223846793005
#define MASTER_random_LCG_musl_c                   1
#define MASTER_random_LCG_VMSMTH$RANDOM_m          0x100000000
#define MASTER_random_LCG_VMSMTH$RANDOM_a          69069 
#define MASTER_random_LCG_VMSMTH$RANDOM_c          1
#define MASTER_random_LCG_ln_rand48_m              0x1000000000000
#define MASTER_random_LCG_ln_rand48_a              25214903917 
#define MASTER_random_LCG_ln_rand48_c              11
#define MASTER_random_LCG_random0_m                134456 
#define MASTER_random_LCG_random0_a                8121 
#define MASTER_random_LCG_random0_c                28411
#define MASTER_random_LCG_dejm_rand48_m            0x1000000000000 
#define MASTER_random_LCG_dejm_rand48_a            25214903917 
#define MASTER_random_LCG_dejm_rand48_c            11
#define MASTER_random_LCG_cc65_1_m                 0x800000 
#define MASTER_random_LCG_cc65_1_a                 65793 
#define MASTER_random_LCG_cc65_1_c                 4282663
#define MASTER_random_LCG_cc65_2_m                 0x100000000
#define MASTER_random_LCG_cc65_2_a                 16843009
#define MASTER_random_LCG_cc65_2_c                 826366247
#define MASTER_random_LCG_cc65_3_m                 0x100000000
#define MASTER_random_LCG_cc65_3_a                 16843009
#define MASTER_random_LCG_cc65_3_c                 3014898611
#define MASTER_random_LCG_RANDU_m                  0x70000000
#define MASTER_random_LCG_RANDU_a                  65539
#define MASTER_random_LCG_RANDU_c                  0

#define MASTER_random_LCG_ZX81                   MASTER_random_LCG_ZX81_m, MASTER_random_LCG_ZX81_a, MASTER_random_LCG_ZX81_c
#define MASTER_random_LCG_randq1                 MASTER_random_LCG_randq1_m, MASTER_random_LCG_randq1_a, MASTER_random_LCG_randq1_c
#define MASTER_random_LCG_borland_c_cpp          MASTER_random_LCG_borland_c_cpp_m, MASTER_random_LCG_borland_c_cpp_a, MASTER_random_LCG_borland_c_cpp_c
#define MASTER_random_LCG_glibc                  MASTER_random_LCG_glibc_m, MASTER_random_LCG_glibc_a, MASTER_random_LCG_glibc_c
#define MASTER_random_LCG_ANSI_c                 MASTER_random_LCG_ANSI_c_m, MASTER_random_LCG_ANSI_c_a, MASTER_random_LCG_ANSI_c_c
#define MASTER_random_LCG_borland_delphi         MASTER_random_LCG_borland_delphi_m, MASTER_random_LCG_borland_delphi_a, MASTER_random_LCG_borland_delphi_c
#define MASTER_random_LCG_turbo_pascal           MASTER_random_LCG_turbo_pascal_m, MASTER_random_LCG_turbo_pascal_a, MASTER_random_LCG_turbo_pascal_c
#define MASTER_random_LCG_microsoft_visual_c_cpp MASTER_random_LCG_microsoft_visual_c_cpp_m, MASTER_random_LCG_microsoft_visual_c_cpp_a, MASTER_random_LCG_microsoft_visual_c_cpp_c
#define MASTER_random_LCG_microsoft_visual_basic MASTER_random_LCG_microsoft_visual_basic_m, MASTER_random_LCG_microsoft_visual_basic_a, MASTER_random_LCG_microsoft_visual_basic_c
#define MASTER_random_LCG_native_api             MASTER_random_LCG_native_api_m, MASTER_random_LCG_native_api_a, MASTER_random_LCG_native_api_c
#define MASTER_random_LCG_minstd_rand0           MASTER_random_LCG_minstd_rand0_m, MASTER_random_LCG_minstd_rand0_a, MASTER_random_LCG_minstd_rand0_c
#define MASTER_random_LCG_minstd_rand            MASTER_random_LCG_minstd_rand_m, MASTER_random_LCG_minstd_rand_a, MASTER_random_LCG_minstd_rand_c
#define MASTER_random_LCG_MMIX                   MASTER_random_LCG_MMIX_m, MASTER_random_LCG_MMIX_a, MASTER_random_LCG_MMIX_c
#define MASTER_random_LCG_MMIX                   MASTER_random_LCG_MMIX_m, MASTER_random_LCG_MMIX_a, MASTER_random_LCG_MMIX_c
#define MASTER_random_LCG_newlib                 MASTER_random_LCG_newlib_m, MASTER_random_LCG_newlib_a, MASTER_random_LCG_newlib_c
#define MASTER_random_LCG_musl                   MASTER_random_LCG_musl_m, MASTER_random_LCG_musl_a, MASTER_random_LCG_musl_c
#define MASTER_random_LCG_ln_rand48              MASTER_random_LCG_ln_rand48_m, MASTER_random_LCG_ln_rand48_a, MASTER_random_LCG_ln_rand48_c
#define MASTER_random_LCG_random0                MASTER_random_LCG_random0_m, MASTER_random_LCG_random0_a, MASTER_random_LCG_random0_c
#define MASTER_random_LCG_dejm_rand48            MASTER_random_LCG_dejm_rand48_m, MASTER_random_LCG_dejm_rand48_a, MASTER_random_LCG_dejm_rand48_c
#define MASTER_random_LCG_cc65_1                 MASTER_random_LCG_cc65_1_m, MASTER_random_LCG_cc65_1_a, MASTER_random_LCG_cc65_1_c
#define MASTER_random_LCG_cc65_2                 MASTER_random_LCG_cc65_2_m, MASTER_random_LCG_cc65_2_a, MASTER_random_LCG_cc65_2_c
#define MASTER_random_LCG_cc65_3                 MASTER_random_LCG_cc65_3_m, MASTER_random_LCG_cc65_3_a, MASTER_random_LCG_cc65_3_c
#define MASTER_random_LCG_RANDU                  MASTER_random_LCG_RANDU_m, MASTER_random_LCG_RANDU_a, MASTER_random_LCG_RANDU_c

#endif /* __MASTER_LCG_ENUMERATION_INCLUDE_H__ */

// be master~
