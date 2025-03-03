
/*
 * Copyright (c) 2025 zELdYT
 *
 * Licensed under the BSD 2-Clause License.
 * See the LICENSE file in the project root for more details.
 */

#ifndef __MASTER_CRC_ENUM_INCLUDE_H__
#define __MASTER_CRC_ENUM_INCLUDE_H__

/* #! Low priority !# */

#include "../../headers/enumeration/master_enum.h"

typedef struct {
	UI4 width;
	UI8 poly, init;
	UI4 refin  : 1;
	UI4 refout : 1;
	UI8 xorout;
} MASTER_CRC;

typedef struct {
	UI4 width;
	UI8 poly, init;
	UI4 refin  : 1;
	UI4 refout : 1;
	UI8 xorout;
	UI8 check, residue;
} MASTER_CRC_EXT;

#define MASTER_CRC_3_GSM ((MASTER_CRC){ 3, 0x3, 0x0, 0, 0, 0x7 })
#define MASTER_CRC_3_ROHC ((MASTER_CRC){ 3, 0x3, 0x7, 1, 1, 0x0 })
#define MASTER_CRC_4_G_704 ((MASTER_CRC){ 4, 0x3, 0x0, 1, 1, 0x0 })
#define MASTER_CRC_4_INTERLAKEN ((MASTER_CRC){ 4, 0x3, 0xF, 0, 0, 0xF })
#define MASTER_CRC_5_EPC_C1G2 ((MASTER_CRC){ 5, 0x09, 0x09, 0, 0, 0x00 })
#define MASTER_CRC_5_G_704 ((MASTER_CRC){ 5, 0x15, 0x00, 1, 1, 0x00 })
#define MASTER_CRC_5_USB ((MASTER_CRC){ 5, 0x05, 0x1F, 1, 1, 0x1F })
#define MASTER_CRC_6_CDMA2000_A ((MASTER_CRC){ 6, 0x27, 0x3F, 0, 0, 0x00 })
#define MASTER_CRC_6_CDMA2000_B ((MASTER_CRC){ 6, 0x07, 0x3F, 0, 0, 0x00 })
#define MASTER_CRC_6_DARC ((MASTER_CRC){ 6, 0x19, 0x00, 1, 1, 0x00 })
#define MASTER_CRC_6_G_704 ((MASTER_CRC){ 6, 0x03, 0x00, 1, 1, 0x00 })
#define MASTER_CRC_6_GSM ((MASTER_CRC){ 6, 0x2F, 0x00, 0, 0, 0x3F })
#define MASTER_CRC_7_MMC ((MASTER_CRC){ 7, 0x09, 0x00, 0, 0, 0x00 })
#define MASTER_CRC_7_ROHC ((MASTER_CRC){ 7, 0x4F, 0x7F, 1, 1, 0x00 })
#define MASTER_CRC_7_UMTS ((MASTER_CRC){ 7, 0x45, 0x00, 0, 0, 0x00 })
#define MASTER_CRC_8_AUTOSAR ((MASTER_CRC){ 8, 0x2F, 0xFF, 0, 0, 0xFF })
#define MASTER_CRC_8_BLUETOOTH ((MASTER_CRC){ 8, 0xA7, 0x00, 1, 1, 0x00 })
#define MASTER_CRC_8_CDMA2000 ((MASTER_CRC){ 8, 0x9B, 0xFF, 0, 0, 0x00 })
#define MASTER_CRC_8_DARC ((MASTER_CRC){ 8, 0x39, 0x00, 1, 1, 0x00 })
#define MASTER_CRC_8_DVB_S2 ((MASTER_CRC){ 8, 0xD5, 0x00, 0, 0, 0x00 })
#define MASTER_CRC_8_GSM_A ((MASTER_CRC){ 8, 0x1D, 0x00, 0, 0, 0x00 })
#define MASTER_CRC_8_GSM_B ((MASTER_CRC){ 8, 0x49, 0x00, 0, 0, 0xFF })
#define MASTER_CRC_8_HITAG ((MASTER_CRC){ 8, 0x1D, 0xFF, 0, 0, 0x00 })
#define MASTER_CRC_8_I_432_1 ((MASTER_CRC){ 8, 0x07, 0x00, 0, 0, 0x55 })
#define MASTER_CRC_8_I_CODE ((MASTER_CRC){ 8, 0x1D, 0xFD, 0, 0, 0x00 })
#define MASTER_CRC_8_LTE ((MASTER_CRC){ 8, 0x9B, 0x00, 0, 0, 0x00 })
#define MASTER_CRC_8_MAXIM_DOW ((MASTER_CRC){ 8, 0x31, 0x00, 1, 1, 0x00 })
#define MASTER_CRC_8_MIFARE_MAD ((MASTER_CRC){ 8, 0x1D, 0xC7, 0, 0, 0x00 })
#define MASTER_CRC_8_NRSC_5 ((MASTER_CRC){ 8, 0x31, 0xFF, 0, 0, 0x00 })
#define MASTER_CRC_8_OPENSAFETY ((MASTER_CRC){ 8, 0x2F, 0x00, 0, 0, 0x00 })
#define MASTER_CRC_8_ROHC ((MASTER_CRC){ 8, 0x07, 0xFF, 1, 1, 0x00 })
#define MASTER_CRC_8_SAE_J1850 ((MASTER_CRC){ 8, 0x1D, 0xFF, 0, 0, 0xFF })
#define MASTER_CRC_8_SMBUS ((MASTER_CRC){ 8, 0x07, 0x00, 0, 0, 0x00 })
#define MASTER_CRC_8_TECH_3250 ((MASTER_CRC){ 8, 0x1D, 0xFF, 1, 1, 0x00 })
#define MASTER_CRC_8_WCDMA ((MASTER_CRC){ 8, 0x9B, 0x00, 1, 1, 0x00 })
#define MASTER_CRC_10_ATM ((MASTER_CRC){ 10, 0x233, 0x000, 0, 0, 0x000 })
#define MASTER_CRC_10_CDMA2000 ((MASTER_CRC){ 10, 0x3D9, 0x3FF, 0, 0, 0x000 })
#define MASTER_CRC_10_GSM ((MASTER_CRC){ 10, 0x175, 0x000, 0, 0, 0x3FF })
#define MASTER_CRC_11_FLEXRAY ((MASTER_CRC){ 11, 0x385, 0x01A, 0, 0, 0x000 })
#define MASTER_CRC_11_UMTS ((MASTER_CRC){ 11, 0x307, 0x000, 0, 0, 0x000 })
#define MASTER_CRC_12_CDMA2000 ((MASTER_CRC){ 12, 0xF13, 0xFFF, 0, 0, 0x000 })
#define MASTER_CRC_12_DECT ((MASTER_CRC){ 12, 0x80F, 0x000, 0, 0, 0x000 })
#define MASTER_CRC_12_GSM ((MASTER_CRC){ 12, 0xD31, 0x000, 0, 0, 0xFFF })
#define MASTER_CRC_12_UMTS ((MASTER_CRC){ 12, 0x80F, 0x000, 0, 1, 0x000 })
#define MASTER_CRC_13_BBC ((MASTER_CRC){ 13, 0x1CF5, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_14_DARC ((MASTER_CRC){ 14, 0x0805, 0x0000, 1, 1, 0x0000 })
#define MASTER_CRC_14_GSM ((MASTER_CRC){ 14, 0x202D, 0x0000, 0, 0, 0x3FFF })
#define MASTER_CRC_15_CAN ((MASTER_CRC){ 15, 0x4599, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_15_MPT1327 ((MASTER_CRC){ 15, 0x6815, 0x0000, 0, 0, 0x0001 })
#define MASTER_CRC_16_ARC ((MASTER_CRC){ 16, 0x8005, 0x0000, 1, 1, 0x0000 })
#define MASTER_CRC_16_CDMA2000 ((MASTER_CRC){ 16, 0xC867, 0xFFFF, 0, 0, 0x0000 })
#define MASTER_CRC_16_CMS ((MASTER_CRC){ 16, 0x8005, 0xFFFF, 0, 0, 0x0000 })
#define MASTER_CRC_16_DDS_110 ((MASTER_CRC){ 16, 0x8005, 0x800D, 0, 0, 0x0000 })
#define MASTER_CRC_16_DECT_R ((MASTER_CRC){ 16, 0x0589, 0x0000, 0, 0, 0x0001 })
#define MASTER_CRC_16_DECT_X ((MASTER_CRC){ 16, 0x0589, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_16_DNP ((MASTER_CRC){ 16, 0x3D65, 0x0000, 1, 1, 0xFFFF })
#define MASTER_CRC_16_EN_13757 ((MASTER_CRC){ 16, 0x3D65, 0x0000, 0, 0, 0xFFFF })
#define MASTER_CRC_16_GENIBUS ((MASTER_CRC){ 16, 0x1021, 0xFFFF, 0, 0, 0xFFFF })
#define MASTER_CRC_16_GSM ((MASTER_CRC){ 16, 0x1021, 0x0000, 0, 0, 0xFFFF })
#define MASTER_CRC_16_IBM_3740 ((MASTER_CRC){ 16, 0x1021, 0xFFFF, 0, 0, 0x0000 })
#define MASTER_CRC_16_IBM_SDLC ((MASTER_CRC){ 16, 0x1021, 0xFFFF, 1, 1, 0xFFFF })
#define MASTER_CRC_16_ISO_IEC_14443_3_A ((MASTER_CRC){ 16, 0x1021, 0xC6C6, 1, 1, 0x0000 })
#define MASTER_CRC_16_KERMIT ((MASTER_CRC){ 16, 0x1021, 0x0000, 1, 1, 0x0000 })
#define MASTER_CRC_16_LJ1200 ((MASTER_CRC){ 16, 0x6F63, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_16_M17 ((MASTER_CRC){ 16, 0x5935, 0xFFFF, 0, 0, 0x0000 })
#define MASTER_CRC_16_MAXIM_DOW ((MASTER_CRC){ 16, 0x8005, 0x0000, 1, 1, 0xFFFF })
#define MASTER_CRC_16_MCRF4XX ((MASTER_CRC){ 16, 0x1021, 0xFFFF, 1, 1, 0x0000 })
#define MASTER_CRC_16_MODBUS ((MASTER_CRC){ 16, 0x8005, 0xFFFF, 1, 1, 0x0000 })
#define MASTER_CRC_16_NRSC_5 ((MASTER_CRC){ 16, 0x080B, 0xFFFF, 1, 1, 0x0000 })
#define MASTER_CRC_16_OPENSAFETY_A ((MASTER_CRC){ 16, 0x5935, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_16_OPENSAFETY_B ((MASTER_CRC){ 16, 0x755B, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_16_PROFIBUS ((MASTER_CRC){ 16, 0x1DCF, 0xFFFF, 0, 0, 0xFFFF })
#define MASTER_CRC_16_RIELLO ((MASTER_CRC){ 16, 0x1021, 0xB2AA, 1, 1, 0x0000 })
#define MASTER_CRC_16_SPI_FUJITSU ((MASTER_CRC){ 16, 0x1021, 0x1D0F, 0, 0, 0x0000 })
#define MASTER_CRC_16_T10_DIF ((MASTER_CRC){ 16, 0x8BB7, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_16_TELEDISK ((MASTER_CRC){ 16, 0xA097, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_16_TMS37157 ((MASTER_CRC){ 16, 0x1021, 0x89EC, 1, 1, 0x0000 })
#define MASTER_CRC_16_UMTS ((MASTER_CRC){ 16, 0x8005, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_16_USB ((MASTER_CRC){ 16, 0x8005, 0xFFFF, 1, 1, 0xFFFF })
#define MASTER_CRC_16_XMODEM ((MASTER_CRC){ 16, 0x1021, 0x0000, 0, 0, 0x0000 })
#define MASTER_CRC_17_CAN_FD ((MASTER_CRC){ 17, 0x1685B, 0x00000, 0, 0, 0x00000 })
#define MASTER_CRC_21_CAN_FD ((MASTER_CRC){ 21, 0x102899, 0x000000, 0, 0, 0x000000 })
#define MASTER_CRC_24_BLE ((MASTER_CRC){ 24, 0x00065B, 0x555555, 1, 1, 0x000000 })
#define MASTER_CRC_24_FLEXRAY_A ((MASTER_CRC){ 24, 0x5D6DCB, 0xFEDCBA, 0, 0, 0x000000 })
#define MASTER_CRC_24_FLEXRAY_B ((MASTER_CRC){ 24, 0x5D6DCB, 0xABCDEF, 0, 0, 0x000000 })
#define MASTER_CRC_24_INTERLAKEN ((MASTER_CRC){ 24, 0x328B63, 0xFFFFFF, 0, 0, 0xFFFFFF })
#define MASTER_CRC_24_LTE_A ((MASTER_CRC){ 24, 0x864CFB, 0x000000, 0, 0, 0x000000 })
#define MASTER_CRC_24_LTE_B ((MASTER_CRC){ 24, 0x800063, 0x000000, 0, 0, 0x000000 })
#define MASTER_CRC_24_OPENPGP ((MASTER_CRC){ 24, 0x864CFB, 0xB704CE, 0, 0, 0x000000 })
#define MASTER_CRC_24_OS_9 ((MASTER_CRC){ 24, 0x800063, 0xFFFFFF, 0, 0, 0xFFFFFF })
#define MASTER_CRC_30_CDMA ((MASTER_CRC){ 30, 0x2030B9C7, 0x3FFFFFFF, 0, 0, 0x3FFFFFFF })
#define MASTER_CRC_31_PHILIPS ((MASTER_CRC){ 31, 0x04C11DB7, 0x7FFFFFFF, 0, 0, 0x7FFFFFFF })
#define MASTER_CRC_32_AIXM ((MASTER_CRC){ 32, 0x814141AB, 0x00000000, 0, 0, 0x00000000 })
#define MASTER_CRC_32_AUTOSAR ((MASTER_CRC){ 32, 0xF4ACFB13, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF })
#define MASTER_CRC_32_BASE91_D ((MASTER_CRC){ 32, 0xA833982B, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF })
#define MASTER_CRC_32_BZIP2 ((MASTER_CRC){ 32, 0x04C11DB7, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF })
#define MASTER_CRC_32_CD_ROM_EDC ((MASTER_CRC){ 32, 0x8001801B, 0x00000000, 1, 1, 0x00000000 })
#define MASTER_CRC_32_CKSUM ((MASTER_CRC){ 32, 0x04C11DB7, 0x00000000, 0, 0, 0xFFFFFFFF })
#define MASTER_CRC_32_ISCSI ((MASTER_CRC){ 32, 0x1EDC6F41, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF })
#define MASTER_CRC_32_ISO_HDLC ((MASTER_CRC){ 32, 0x04C11DB7, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF })
#define MASTER_CRC_32_JAMCRC ((MASTER_CRC){ 32, 0x04C11DB7, 0xFFFFFFFF, 1, 1, 0x00000000 })
#define MASTER_CRC_32_MEF ((MASTER_CRC){ 32, 0x741B8CD7, 0xFFFFFFFF, 1, 1, 0x00000000 })
#define MASTER_CRC_32_MPEG_2 ((MASTER_CRC){ 32, 0x04C11DB7, 0xFFFFFFFF, 0, 0, 0x00000000 })
#define MASTER_CRC_32_XFER ((MASTER_CRC){ 32, 0x000000AF, 0x00000000, 0, 0, 0x00000000 })
#define MASTER_CRC_40_GSM ((MASTER_CRC){ 40, 0x0004820009, 0x0000000000, 0, 0, 0xFFFFFFFFFF })
#define MASTER_CRC_64_ECMA_182 ((MASTER_CRC){ 64, 0x42F0E1EBA9EA3693, 0x0000000000000000, 0, 0, 0x0000000000000000 })
#define MASTER_CRC_64_GO_ISO ((MASTER_CRC){ 64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, 1, 1, 0xFFFFFFFFFFFFFFFF })
#define MASTER_CRC_64_MS ((MASTER_CRC){ 64, 0x259C84CBA6426349, 0xFFFFFFFFFFFFFFFF, 1, 1, 0x0000000000000000 })
#define MASTER_CRC_64_NVME ((MASTER_CRC){ 64, 0xAD93D23594C93659, 0xFFFFFFFFFFFFFFFF, 1, 1, 0xFFFFFFFFFFFFFFFF })
#define MASTER_CRC_64_REDIS ((MASTER_CRC){ 64, 0xAD93D23594C935A9, 0x0000000000000000, 1, 1, 0x0000000000000000 })
#define MASTER_CRC_64_WE ((MASTER_CRC){ 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0, 0, 0xFFFFFFFFFFFFFFFF })
#define MASTER_CRC_64_XZ ((MASTER_CRC){ 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 1, 1, 0xFFFFFFFFFFFFFFFF })
#define MASTER_CRC_82_DARC ((MASTER_CRC){ 82, 0x0308C0111011401440411, 0x000000000000000000000, 1, 1, 0x000000000000000000000 })

#define MASTER_CRC_EXT_3_GSM ((MASTER_CRC_EXT){ 3, 0x3, 0x0, 0, 0, 0x7, 0x4, 0x2 })
#define MASTER_CRC_EXT_3_ROH ((MASTER_CRC_EXT){ 3, 0x3, 0x7, 1, 1, 0x0, 0x6, 0x0 })
#define MASTER_CRC_EXT_4_G_704 ((MASTER_CRC_EXT){ 4, 0x3, 0x0, 1, 1, 0x0, 0x7, 0x0 })
#define MASTER_CRC_EXT_4_INTERLAKEN ((MASTER_CRC_EXT){ 4, 0x3, 0xF, 0, 0, 0xF, 0xB, 0x2 })
#define MASTER_CRC_EXT_5_EPC_C1G2 ((MASTER_CRC_EXT){ 5, 0x09, 0x09, 0, 0, 0x00, 0x00, 0x00 })
#define MASTER_CRC_EXT_5_G_704 ((MASTER_CRC_EXT){ 5, 0x15, 0x00, 1, 1, 0x00, 0x07, 0x00 })
#define MASTER_CRC_EXT_5_USB ((MASTER_CRC_EXT){ 5, 0x05, 0x1F, 1, 1, 0x1F, 0x19, 0x06 })
#define MASTER_CRC_EXT_6_CDMA2000_A ((MASTER_CRC_EXT){ 6, 0x27, 0x3F, 0, 0, 0x00, 0x0D, 0x00 })
#define MASTER_CRC_EXT_6_CDMA2000_B ((MASTER_CRC_EXT){ 6, 0x07, 0x3F, 0, 0, 0x00, 0x3B, 0x00 })
#define MASTER_CRC_EXT_6_DA ((MASTER_CRC_EXT){ 6, 0x19, 0x00, 1, 1, 0x00, 0x26, 0x00 })
#define MASTER_CRC_EXT_6_G_704 ((MASTER_CRC_EXT){ 6, 0x03, 0x00, 1, 1, 0x00, 0x06, 0x00 })
#define MASTER_CRC_EXT_6_GSM ((MASTER_CRC_EXT){ 6, 0x2F, 0x00, 0, 0, 0x3F, 0x13, 0x3A })
#define MASTER_CRC_EXT_7_MM ((MASTER_CRC_EXT){ 7, 0x09, 0x00, 0, 0, 0x00, 0x75, 0x00 })
#define MASTER_CRC_EXT_7_ROH ((MASTER_CRC_EXT){ 7, 0x4F, 0x7F, 1, 1, 0x00, 0x53, 0x00 })
#define MASTER_CRC_EXT_7_UMTS ((MASTER_CRC_EXT){ 7, 0x45, 0x00, 0, 0, 0x00, 0x61, 0x00 })
#define MASTER_CRC_EXT_8_AUTOSA ((MASTER_CRC_EXT){ 8, 0x2F, 0xFF, 0, 0, 0xFF, 0xDF, 0x42 })
#define MASTER_CRC_EXT_8_BLUETOOTH ((MASTER_CRC_EXT){ 8, 0xA7, 0x00, 1, 1, 0x00, 0x26, 0x00 })
#define MASTER_CRC_EXT_8_CDMA2000 ((MASTER_CRC_EXT){ 8, 0x9B, 0xFF, 0, 0, 0x00, 0xDA, 0x00 })
#define MASTER_CRC_EXT_8_DA ((MASTER_CRC_EXT){ 8, 0x39, 0x00, 1, 1, 0x00, 0x15, 0x00 })
#define MASTER_CRC_EXT_8_DVB_S2 ((MASTER_CRC_EXT){ 8, 0xD5, 0x00, 0, 0, 0x00, 0xBC, 0x00 })
#define MASTER_CRC_EXT_8_GSM_A ((MASTER_CRC_EXT){ 8, 0x1D, 0x00, 0, 0, 0x00, 0x37, 0x00 })
#define MASTER_CRC_EXT_8_GSM_B ((MASTER_CRC_EXT){ 8, 0x49, 0x00, 0, 0, 0xFF, 0x94, 0x53 })
#define MASTER_CRC_EXT_8_HITAG ((MASTER_CRC_EXT){ 8, 0x1D, 0xFF, 0, 0, 0x00, 0xB4, 0x00 })
#define MASTER_CRC_EXT_8_I_432_1 ((MASTER_CRC_EXT){ 8, 0x07, 0x00, 0, 0, 0x55, 0xA1, 0xAC })
#define MASTER_CRC_EXT_8_I_CODE ((MASTER_CRC_EXT){ 8, 0x1D, 0xFD, 0, 0, 0x00, 0x7E, 0x00 })
#define MASTER_CRC_EXT_8_LTE ((MASTER_CRC_EXT){ 8, 0x9B, 0x00, 0, 0, 0x00, 0xEA, 0x00 })
#define MASTER_CRC_EXT_8_MAXIM_DOW ((MASTER_CRC_EXT){ 8, 0x31, 0x00, 1, 1, 0x00, 0xA1, 0x00 })
#define MASTER_CRC_EXT_8_MIFARE_MAD ((MASTER_CRC_EXT){ 8, 0x1D, 0xC7, 0, 0, 0x00, 0x99, 0x00 })
#define MASTER_CRC_EXT_8_NRSC_5 ((MASTER_CRC_EXT){ 8, 0x31, 0xFF, 0, 0, 0x00, 0xF7, 0x00 })
#define MASTER_CRC_EXT_8_OPENSAFETY ((MASTER_CRC_EXT){ 8, 0x2F, 0x00, 0, 0, 0x00, 0x3E, 0x00 })
#define MASTER_CRC_EXT_8_ROH ((MASTER_CRC_EXT){ 8, 0x07, 0xFF, 1, 1, 0x00, 0xD0, 0x00 })
#define MASTER_CRC_EXT_8_SAE_J1850 ((MASTER_CRC_EXT){ 8, 0x1D, 0xFF, 0, 0, 0xFF, 0x4B, 0xC4 })
#define MASTER_CRC_EXT_8_SMBUS ((MASTER_CRC_EXT){ 8, 0x07, 0x00, 0, 0, 0x00, 0xF4, 0x00 })
#define MASTER_CRC_EXT_8_TECH_3250 ((MASTER_CRC_EXT){ 8, 0x1D, 0xFF, 1, 1, 0x00, 0x97, 0x00 })
#define MASTER_CRC_EXT_8_WCDMA ((MASTER_CRC_EXT){ 8, 0x9B, 0x00, 1, 1, 0x00, 0x25, 0x00 })
#define MASTER_CRC_EXT_10_ATM ((MASTER_CRC_EXT){ 10, 0x233, 0x000, 0, 0, 0x000, 0x199, 0x000 })
#define MASTER_CRC_EXT_10_CDMA2000 ((MASTER_CRC_EXT){ 10, 0x3D9, 0x3FF, 0, 0, 0x000, 0x233, 0x000 })
#define MASTER_CRC_EXT_10_GSM ((MASTER_CRC_EXT){ 10, 0x175, 0x000, 0, 0, 0x3FF, 0x12A, 0x0C6 })
#define MASTER_CRC_EXT_11_FLEXRAY ((MASTER_CRC_EXT){ 11, 0x385, 0x01A, 0, 0, 0x000, 0x5A3, 0x000 })
#define MASTER_CRC_EXT_11_UMTS ((MASTER_CRC_EXT){ 11, 0x307, 0x000, 0, 0, 0x000, 0x061, 0x000 })
#define MASTER_CRC_EXT_12_CDMA2000 ((MASTER_CRC_EXT){ 12, 0xF13, 0xFFF, 0, 0, 0x000, 0xD4D, 0x000 })
#define MASTER_CRC_EXT_12_DECT ((MASTER_CRC_EXT){ 12, 0x80F, 0x000, 0, 0, 0x000, 0xF5B, 0x000 })
#define MASTER_CRC_EXT_12_GSM ((MASTER_CRC_EXT){ 12, 0xD31, 0x000, 0, 0, 0xFFF, 0xB34, 0x178 })
#define MASTER_CRC_EXT_12_UMTS ((MASTER_CRC_EXT){ 12, 0x80F, 0x000, 0, 1, 0x000, 0xDAF, 0x000 })
#define MASTER_CRC_EXT_13_BB ((MASTER_CRC_EXT){ 13, 0x1CF5, 0x0000, 0, 0, 0x0000, 0x04FA, 0x0000 })
#define MASTER_CRC_EXT_14_DA ((MASTER_CRC_EXT){ 14, 0x0805, 0x0000, 1, 1, 0x0000, 0x082D, 0x0000 })
#define MASTER_CRC_EXT_14_GSM ((MASTER_CRC_EXT){ 14, 0x202D, 0x0000, 0, 0, 0x3FFF, 0x30AE, 0x031E })
#define MASTER_CRC_EXT_15_CAN ((MASTER_CRC_EXT){ 15, 0x4599, 0x0000, 0, 0, 0x0000, 0x059E, 0x0000 })
#define MASTER_CRC_EXT_15_MPT1327 ((MASTER_CRC_EXT){ 15, 0x6815, 0x0000, 0, 0, 0x0001, 0x2566, 0x6815 })
#define MASTER_CRC_EXT_16_A ((MASTER_CRC_EXT){ 16, 0x8005, 0x0000, 1, 1, 0x0000, 0xBB3D, 0x0000 })#define MASTER_CRC_EXT_16_CDMA2000 ((MASTER_CRC_EXT){ 16, 0xC867, 0xFFFF, 0, 0, 0x0000, 0x4C06, 0x0000 })
#define MASTER_CRC_EXT_16_CMS ((MASTER_CRC_EXT){ 16, 0x8005, 0xFFFF, 0, 0, 0x0000, 0xAEE7, 0x0000 })
#define MASTER_CRC_EXT_16_DDS_110 ((MASTER_CRC_EXT){ 16, 0x8005, 0x800D, 0, 0, 0x0000, 0x9ECF, 0x0000 })
#define MASTER_CRC_EXT_16_DECT ((MASTER_CRC_EXT){ 16, 0x0589, 0x0000, 0, 0, 0x0001, 0x007E, 0x0589 })
#define MASTER_CRC_EXT_16_DECT_X ((MASTER_CRC_EXT){ 16, 0x0589, 0x0000, 0, 0, 0x0000, 0x007F, 0x0000 })
#define MASTER_CRC_EXT_16_DNP ((MASTER_CRC_EXT){ 16, 0x3D65, 0x0000, 1, 1, 0xFFFF, 0xEA82, 0x66C5 })
#define MASTER_CRC_EXT_16_EN_13757 ((MASTER_CRC_EXT){ 16, 0x3D65, 0x0000, 0, 0, 0xFFFF, 0xC2B7, 0xA366 })
#define MASTER_CRC_EXT_16_GENIBUS ((MASTER_CRC_EXT){ 16, 0x1021, 0xFFFF, 0, 0, 0xFFFF, 0xD64E, 0x1D0F })
#define MASTER_CRC_EXT_16_GSM ((MASTER_CRC_EXT){ 16, 0x1021, 0x0000, 0, 0, 0xFFFF, 0xCE3C, 0x1D0F })
#define MASTER_CRC_EXT_16_IBM_3740 ((MASTER_CRC_EXT){ 16, 0x1021, 0xFFFF, 0, 0, 0x0000, 0x29B1, 0x0000 })
#define MASTER_CRC_EXT_16_IBM_SDL ((MASTER_CRC_EXT){ 16, 0x1021, 0xFFFF, 1, 1, 0xFFFF, 0x906E, 0xF0B8 })
#define MASTER_CRC_EXT_16_ISO_IEC_14443_3_A ((MASTER_CRC_EXT){ 16, 0x1021, 0xC6C6, 1, 1, 0x0000, 0xBF05, 0x0000 })
#define MASTER_CRC_EXT_16_KERMIT ((MASTER_CRC_EXT){ 16, 0x1021, 0x0000, 1, 1, 0x0000, 0x2189, 0x0000 })
#define MASTER_CRC_EXT_16_LJ1200 ((MASTER_CRC_EXT){ 16, 0x6F63, 0x0000, 0, 0, 0x0000, 0xBDF4, 0x0000 })
#define MASTER_CRC_EXT_16_M17 ((MASTER_CRC_EXT){ 16, 0x5935, 0xFFFF, 0, 0, 0x0000, 0x772B, 0x0000 })
#define MASTER_CRC_EXT_16_MAXIM_DOW ((MASTER_CRC_EXT){ 16, 0x8005, 0x0000, 1, 1, 0xFFFF, 0x44C2, 0xB001 })
#define MASTER_CRC_EXT_16_MCRF4XX ((MASTER_CRC_EXT){ 16, 0x1021, 0xFFFF, 1, 1, 0x0000, 0x6F91, 0x0000 })
#define MASTER_CRC_EXT_16_MODBUS ((MASTER_CRC_EXT){ 16, 0x8005, 0xFFFF, 1, 1, 0x0000, 0x4B37, 0x0000 })
#define MASTER_CRC_EXT_16_NRSC_5 ((MASTER_CRC_EXT){ 16, 0x080B, 0xFFFF, 1, 1, 0x0000, 0xA066, 0x0000 })
#define MASTER_CRC_EXT_16_OPENSAFETY_A ((MASTER_CRC_EXT){ 16, 0x5935, 0x0000, 0, 0, 0x0000, 0x5D38, 0x0000 })
#define MASTER_CRC_EXT_16_OPENSAFETY_B ((MASTER_CRC_EXT){ 16, 0x755B, 0x0000, 0, 0, 0x0000, 0x20FE, 0x0000 })
#define MASTER_CRC_EXT_16_PROFIBUS ((MASTER_CRC_EXT){ 16, 0x1DCF, 0xFFFF, 0, 0, 0xFFFF, 0xA819, 0xE394 })
#define MASTER_CRC_EXT_16_RIELLO ((MASTER_CRC_EXT){ 16, 0x1021, 0xB2AA, 1, 1, 0x0000, 0x63D0, 0x0000 })
#define MASTER_CRC_EXT_16_SPI_FUJITSU ((MASTER_CRC_EXT){ 16, 0x1021, 0x1D0F, 0, 0, 0x0000, 0xE5CC, 0x0000 })
#define MASTER_CRC_EXT_16_T10_DIF ((MASTER_CRC_EXT){ 16, 0x8BB7, 0x0000, 0, 0, 0x0000, 0xD0DB, 0x0000 })
#define MASTER_CRC_EXT_16_TELEDISK ((MASTER_CRC_EXT){ 16, 0xA097, 0x0000, 0, 0, 0x0000, 0x0FB3, 0x0000 })
#define MASTER_CRC_EXT_16_TMS37157 ((MASTER_CRC_EXT){ 16, 0x1021, 0x89EC, 1, 1, 0x0000, 0x26B1, 0x0000 })
#define MASTER_CRC_EXT_16_UMTS ((MASTER_CRC_EXT){ 16, 0x8005, 0x0000, 0, 0, 0x0000, 0xFEE8, 0x0000 })
#define MASTER_CRC_EXT_16_USB ((MASTER_CRC_EXT){ 16, 0x8005, 0xFFFF, 1, 1, 0xFFFF, 0xB4C8, 0xB001 })
#define MASTER_CRC_EXT_16_XMODEM ((MASTER_CRC_EXT){ 16, 0x1021, 0x0000, 0, 0, 0x0000, 0x31C3, 0x0000 })
#define MASTER_CRC_EXT_17_CAN_FD ((MASTER_CRC_EXT){ 17, 0x1685B, 0x00000, 0, 0, 0x00000, 0x04F03, 0x00000 })
#define MASTER_CRC_EXT_21_CAN_FD ((MASTER_CRC_EXT){ 21, 0x102899, 0x000000, 0, 0, 0x000000, 0x0ED841, 0x000000 })
#define MASTER_CRC_EXT_24_BLE ((MASTER_CRC_EXT){ 24, 0x00065B, 0x555555, 1, 1, 0x000000, 0xC25A56, 0x000000 })
#define MASTER_CRC_EXT_24_FLEXRAY_A ((MASTER_CRC_EXT){ 24, 0x5D6DCB, 0xFEDCBA, 0, 0, 0x000000, 0x7979BD, 0x000000 })
#define MASTER_CRC_EXT_24_FLEXRAY_B ((MASTER_CRC_EXT){ 24, 0x5D6DCB, 0xABCDEF, 0, 0, 0x000000, 0x1F23B8, 0x000000 })
#define MASTER_CRC_EXT_24_INTERLAKEN ((MASTER_CRC_EXT){ 24, 0x328B63, 0xFFFFFF, 0, 0, 0xFFFFFF, 0xB4F3E6, 0x144E63 })
#define MASTER_CRC_EXT_24_LTE_A ((MASTER_CRC_EXT){ 24, 0x864CFB, 0x000000, 0, 0, 0x000000, 0xCDE703, 0x000000 })
#define MASTER_CRC_EXT_24_LTE_B ((MASTER_CRC_EXT){ 24, 0x800063, 0x000000, 0, 0, 0x000000, 0x23EF52, 0x000000 })
#define MASTER_CRC_EXT_24_OPENPGP ((MASTER_CRC_EXT){ 24, 0x864CFB, 0xB704CE, 0, 0, 0x000000, 0x21CF02, 0x000000 })
#define MASTER_CRC_EXT_24_OS_9 ((MASTER_CRC_EXT){ 24, 0x800063, 0xFFFFFF, 0, 0, 0xFFFFFF, 0x200FA5, 0x800FE3 })
#define MASTER_CRC_EXT_30_CDMA ((MASTER_CRC_EXT){ 30, 0x2030B9C7, 0x3FFFFFFF, 0, 0, 0x3FFFFFFF, 0x04C34ABF, 0x34EFA55A })
#define MASTER_CRC_EXT_31_PHILIPS ((MASTER_CRC_EXT){ 31, 0x04C11DB7, 0x7FFFFFFF, 0, 0, 0x7FFFFFFF, 0x0CE9E46C, 0x4EAF26F1 })
#define MASTER_CRC_EXT_32_AIXM ((MASTER_CRC_EXT){ 32, 0x814141AB, 0x00000000, 0, 0, 0x00000000, 0x3010BF7F, 0x00000000 })
#define MASTER_CRC_EXT_32_AUTOSA ((MASTER_CRC_EXT){ 32, 0xF4ACFB13, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF, 0x1697D06A, 0x904CDDBF })
#define MASTER_CRC_EXT_32_BASE91_D ((MASTER_CRC_EXT){ 32, 0xA833982B, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF, 0x87315576, 0x45270551 })
#define MASTER_CRC_EXT_32_BZIP2 ((MASTER_CRC_EXT){ 32, 0x04C11DB7, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF, 0xFC891918, 0xC704DD7B })
#define MASTER_CRC_EXT_32_CD_ROM_ED ((MASTER_CRC_EXT){ 32, 0x8001801B, 0x00000000, 1, 1, 0x00000000, 0x6EC2EDC4, 0x00000000 })
#define MASTER_CRC_EXT_32_CKSUM ((MASTER_CRC_EXT){ 32, 0x04C11DB7, 0x00000000, 0, 0, 0xFFFFFFFF, 0x765E7680, 0xC704DD7B })
#define MASTER_CRC_EXT_32_ISCSI ((MASTER_CRC_EXT){ 32, 0x1EDC6F41, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF, 0xE3069283, 0xB798B438 })
#define MASTER_CRC_EXT_32_ISO_HDL ((MASTER_CRC_EXT){ 32, 0x04C11DB7, 0xFFFFFFFF, 1, 1, 0xFFFFFFFF, 0xCBF43926, 0xDEBB20E3 })
#define MASTER_CRC_EXT_32_JAM ((MASTER_CRC_EXT){ 32, 0x04C11DB7, 0xFFFFFFFF, 1, 1, 0x00000000, 0x340BC6D9, 0x00000000 })
#define MASTER_CRC_EXT_32_MEF ((MASTER_CRC_EXT){ 32, 0x741B8CD7, 0xFFFFFFFF, 1, 1, 0x00000000, 0xD2C22F51, 0x00000000 })
#define MASTER_CRC_EXT_32_MPEG_2 ((MASTER_CRC_EXT){ 32, 0x04C11DB7, 0xFFFFFFFF, 0, 0, 0x00000000, 0x0376E6E7, 0x00000000 })
#define MASTER_CRC_EXT_32_XFE ((MASTER_CRC_EXT){ 32, 0x000000AF, 0x00000000, 0, 0, 0x00000000, 0xBD0BE338, 0x00000000 })
#define MASTER_CRC_EXT_40_GSM ((MASTER_CRC_EXT){ 40, 0x0004820009, 0x0000000000, 0, 0, 0xFFFFFFFFFF, 0xD4164FC646, 0xC4FF8071FF })
#define MASTER_CRC_EXT_64_ECMA_182 ((MASTER_CRC_EXT){ 64, 0x42F0E1EBA9EA3693, 0x0000000000000000, 0, 0, 0x0000000000000000, 0x6C40DF5F0B497347, 0x0000000000000000 })
#define MASTER_CRC_EXT_64_GO_ISO ((MASTER_CRC_EXT){ 64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, 1, 1, 0xFFFFFFFFFFFFFFFF, 0xB90956C775A41001, 0x5300000000000000 })
#define MASTER_CRC_EXT_64_MS ((MASTER_CRC_EXT){ 64, 0x259C84CBA6426349, 0xFFFFFFFFFFFFFFFF, 1, 1, 0x0000000000000000, 0x75D4B74F024ECEEA, 0x0000000000000000 })
#define MASTER_CRC_EXT_64_NVME ((MASTER_CRC_EXT){ 64, 0xAD93D23594C93659, 0xFFFFFFFFFFFFFFFF, 1, 1, 0xFFFFFFFFFFFFFFFF, 0xAE8B14860A799888, 0xF310303B2B6F6E42 })
#define MASTER_CRC_EXT_64_REDIS ((MASTER_CRC_EXT){ 64, 0xAD93D23594C935A9, 0x0000000000000000, 1, 1, 0x0000000000000000, 0xE9C6D914C4B8D9CA, 0x0000000000000000 })
#define MASTER_CRC_EXT_64_WE ((MASTER_CRC_EXT){ 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 0, 0, 0xFFFFFFFFFFFFFFFF, 0x62EC59E3F1A4F00A, 0xFCACBEBD5931A992 })
#define MASTER_CRC_EXT_64_XZ ((MASTER_CRC_EXT){ 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 1, 1, 0xFFFFFFFFFFFFFFFF, 0x995DC9BBDF1939FA, 0x49958C9ABD7D353F })
#define MASTER_CRC_EXT_82_DARC ((MASTER_CRC_EXT){ 82, 0x0308C0111011401440411, 0x000000000000000000000, 1, 1, 0x000000000000000000000, 0x09EA83F625023801FD612, 0x000000000000000000000 })

#endif /* __MASTER_CRC_ENUM_INCLUDE_H__ */

// be master~
