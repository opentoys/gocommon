package gmsm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var sm4_sbox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

// sbox_t[j] == L(sbox[j]).
var sm4_sbox_t0 = [256]uint32{
	0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787,
	0xC93DF4F4, 0x6BB5DEDE, 0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B,
	0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414, 0x872BACAC, 0xFB669D9D,
	0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
	0x02A8AAAA, 0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A,
	0x1E061818, 0xFD9B6666, 0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3,
	0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9, 0xFF33CCCC, 0x04555151,
	0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
	0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020,
	0x48EBA3A3, 0xC1975656, 0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB,
	0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A, 0x5B461D1D, 0x1B071C1C,
	0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
	0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616,
	0x734E3D3D, 0x08AAA2A2, 0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA,
	0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E, 0x18FBE3E3, 0x47E8AFAF,
	0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4,
	0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161,
	0x95D24747, 0x2AA08A8A, 0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC,
	0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E, 0x84D75353, 0x00000000,
	0x5E471919, 0x0B565D5D, 0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
	0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313,
	0xE8CB2323, 0xE69C7A7A, 0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B,
	0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6, 0x2FA18E8E, 0x2BF4DFDF,
	0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
	0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0,
	0x721A6868, 0x01545555, 0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0,
	0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F, 0x691D7474, 0x2EF5DBDB,
	0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
	0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x07A9AEAE, 0x390D3434, 0x1F524D4D,
	0x764F3939, 0xD36EBDBD, 0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515,
	0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC, 0x0F030C0C, 0x03FCFFFF,
	0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
	0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777,
	0x4CBEF2F2, 0x837EFDFD, 0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505,
	0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363, 0x220A2828, 0xC5C20707,
	0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
	0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797,
	0x64B6D2D2, 0x70B2C2C2, 0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929,
	0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9, 0xF1649595, 0x5DBBE6E6,
	0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
	0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373,
	0x794C3535, 0xA0208080, 0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8,
	0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121,
}

var sm4_sbox_t1 = [256]uint32{
	0x5B8ED55B, 0x42D09242, 0xA74DEAA7, 0xFB06FDFB, 0x33FCCF33, 0x8765E287,
	0xF4C93DF4, 0xDE6BB5DE, 0x584E1658, 0xDA6EB4DA, 0x50441450, 0x0BCAC10B,
	0xA08828A0, 0xEF17F8EF, 0xB09C2CB0, 0x14110514, 0xAC872BAC, 0x9DFB669D,
	0x6AF2986A, 0xD9AE77D9, 0xA8822AA8, 0xFA46BCFA, 0x10140410, 0x0FCFC00F,
	0xAA02A8AA, 0x11544511, 0x4C5F134C, 0x98BE2698, 0x256D4825, 0x1A9E841A,
	0x181E0618, 0x66FD9B66, 0x72EC9E72, 0x094A4309, 0x41105141, 0xD324F7D3,
	0x46D59346, 0xBF53ECBF, 0x62F89A62, 0xE9927BE9, 0xCCFF33CC, 0x51045551,
	0x2C270B2C, 0x0D4F420D, 0xB759EEB7, 0x3FF3CC3F, 0xB21CAEB2, 0x89EA6389,
	0x9374E793, 0xCE7FB1CE, 0x706C1C70, 0xA60DABA6, 0x27EDCA27, 0x20280820,
	0xA348EBA3, 0x56C19756, 0x02808202, 0x7FA3DC7F, 0x52C49652, 0xEB12F9EB,
	0xD5A174D5, 0x3EB38D3E, 0xFCC33FFC, 0x9A3EA49A, 0x1D5B461D, 0x1C1B071C,
	0x9E3BA59E, 0xF30CFFF3, 0xCF3FF0CF, 0xCDBF72CD, 0x5C4B175C, 0xEA52B8EA,
	0x0E8F810E, 0x653D5865, 0xF0CC3CF0, 0x647D1964, 0x9B7EE59B, 0x16918716,
	0x3D734E3D, 0xA208AAA2, 0xA1C869A1, 0xADC76AAD, 0x06858306, 0xCA7AB0CA,
	0xC5B570C5, 0x91F46591, 0x6BB2D96B, 0x2EA7892E, 0xE318FBE3, 0xAF47E8AF,
	0x3C330F3C, 0x2D674A2D, 0xC1B071C1, 0x590E5759, 0x76E99F76, 0xD4E135D4,
	0x78661E78, 0x90B42490, 0x38360E38, 0x79265F79, 0x8DEF628D, 0x61385961,
	0x4795D247, 0x8A2AA08A, 0x94B12594, 0x88AA2288, 0xF18C7DF1, 0xECD73BEC,
	0x04050104, 0x84A52184, 0xE19879E1, 0x1E9B851E, 0x5384D753, 0x00000000,
	0x195E4719, 0x5D0B565D, 0x7EE39D7E, 0x4F9FD04F, 0x9CBB279C, 0x491A5349,
	0x317C4D31, 0xD8EE36D8, 0x080A0208, 0x9F7BE49F, 0x8220A282, 0x13D4C713,
	0x23E8CB23, 0x7AE69C7A, 0xAB42E9AB, 0xFE43BDFE, 0x2AA2882A, 0x4B9AD14B,
	0x01404101, 0x1FDBC41F, 0xE0D838E0, 0xD661B7D6, 0x8E2FA18E, 0xDF2BF4DF,
	0xCB3AF1CB, 0x3BF6CD3B, 0xE71DFAE7, 0x85E56085, 0x54411554, 0x8625A386,
	0x8360E383, 0xBA16ACBA, 0x75295C75, 0x9234A692, 0x6EF7996E, 0xD0E434D0,
	0x68721A68, 0x55015455, 0xB619AFB6, 0x4EDF914E, 0xC8FA32C8, 0xC0F030C0,
	0xD721F6D7, 0x32BC8E32, 0xC675B3C6, 0x8F6FE08F, 0x74691D74, 0xDB2EF5DB,
	0x8B6AE18B, 0xB8962EB8, 0x0A8A800A, 0x99FE6799, 0x2BE2C92B, 0x81E06181,
	0x03C0C303, 0xA48D29A4, 0x8CAF238C, 0xAE07A9AE, 0x34390D34, 0x4D1F524D,
	0x39764F39, 0xBDD36EBD, 0x5781D657, 0x6FB7D86F, 0xDCEB37DC, 0x15514415,
	0x7BA6DD7B, 0xF709FEF7, 0x3AB68C3A, 0xBC932FBC, 0x0C0F030C, 0xFF03FCFF,
	0xA9C26BA9, 0xC9BA73C9, 0xB5D96CB5, 0xB1DC6DB1, 0x6D375A6D, 0x45155045,
	0x36B98F36, 0x6C771B6C, 0xBE13ADBE, 0x4ADA904A, 0xEE57B9EE, 0x77A9DE77,
	0xF24CBEF2, 0xFD837EFD, 0x44551144, 0x67BDDA67, 0x712C5D71, 0x05454005,
	0x7C631F7C, 0x40501040, 0x69325B69, 0x63B8DB63, 0x28220A28, 0x07C5C207,
	0xC4F531C4, 0x22A88A22, 0x9631A796, 0x37F9CE37, 0xED977AED, 0xF649BFF6,
	0xB4992DB4, 0xD1A475D1, 0x4390D343, 0x485A1248, 0xE258BAE2, 0x9771E697,
	0xD264B6D2, 0xC270B2C2, 0x26AD8B26, 0xA5CD68A5, 0x5ECB955E, 0x29624B29,
	0x303C0C30, 0x5ACE945A, 0xDDAB76DD, 0xF9867FF9, 0x95F16495, 0xE65DBBE6,
	0xC735F2C7, 0x242D0924, 0x17D1C617, 0xB9D66FB9, 0x1BDEC51B, 0x12948612,
	0x60781860, 0xC330F3C3, 0xF5897CF5, 0xB35CEFB3, 0xE8D23AE8, 0x73ACDF73,
	0x35794C35, 0x80A02080, 0xE59D78E5, 0xBB56EDBB, 0x7D235E7D, 0xF8C63EF8,
	0x5F8BD45F, 0x2FE7C82F, 0xE4DD39E4, 0x21684921,
}

var sm4_sbox_t2 = [256]uint32{
	0x5B5B8ED5, 0x4242D092, 0xA7A74DEA, 0xFBFB06FD, 0x3333FCCF, 0x878765E2,
	0xF4F4C93D, 0xDEDE6BB5, 0x58584E16, 0xDADA6EB4, 0x50504414, 0x0B0BCAC1,
	0xA0A08828, 0xEFEF17F8, 0xB0B09C2C, 0x14141105, 0xACAC872B, 0x9D9DFB66,
	0x6A6AF298, 0xD9D9AE77, 0xA8A8822A, 0xFAFA46BC, 0x10101404, 0x0F0FCFC0,
	0xAAAA02A8, 0x11115445, 0x4C4C5F13, 0x9898BE26, 0x25256D48, 0x1A1A9E84,
	0x18181E06, 0x6666FD9B, 0x7272EC9E, 0x09094A43, 0x41411051, 0xD3D324F7,
	0x4646D593, 0xBFBF53EC, 0x6262F89A, 0xE9E9927B, 0xCCCCFF33, 0x51510455,
	0x2C2C270B, 0x0D0D4F42, 0xB7B759EE, 0x3F3FF3CC, 0xB2B21CAE, 0x8989EA63,
	0x939374E7, 0xCECE7FB1, 0x70706C1C, 0xA6A60DAB, 0x2727EDCA, 0x20202808,
	0xA3A348EB, 0x5656C197, 0x02028082, 0x7F7FA3DC, 0x5252C496, 0xEBEB12F9,
	0xD5D5A174, 0x3E3EB38D, 0xFCFCC33F, 0x9A9A3EA4, 0x1D1D5B46, 0x1C1C1B07,
	0x9E9E3BA5, 0xF3F30CFF, 0xCFCF3FF0, 0xCDCDBF72, 0x5C5C4B17, 0xEAEA52B8,
	0x0E0E8F81, 0x65653D58, 0xF0F0CC3C, 0x64647D19, 0x9B9B7EE5, 0x16169187,
	0x3D3D734E, 0xA2A208AA, 0xA1A1C869, 0xADADC76A, 0x06068583, 0xCACA7AB0,
	0xC5C5B570, 0x9191F465, 0x6B6BB2D9, 0x2E2EA789, 0xE3E318FB, 0xAFAF47E8,
	0x3C3C330F, 0x2D2D674A, 0xC1C1B071, 0x59590E57, 0x7676E99F, 0xD4D4E135,
	0x7878661E, 0x9090B424, 0x3838360E, 0x7979265F, 0x8D8DEF62, 0x61613859,
	0x474795D2, 0x8A8A2AA0, 0x9494B125, 0x8888AA22, 0xF1F18C7D, 0xECECD73B,
	0x04040501, 0x8484A521, 0xE1E19879, 0x1E1E9B85, 0x535384D7, 0x00000000,
	0x19195E47, 0x5D5D0B56, 0x7E7EE39D, 0x4F4F9FD0, 0x9C9CBB27, 0x49491A53,
	0x31317C4D, 0xD8D8EE36, 0x08080A02, 0x9F9F7BE4, 0x828220A2, 0x1313D4C7,
	0x2323E8CB, 0x7A7AE69C, 0xABAB42E9, 0xFEFE43BD, 0x2A2AA288, 0x4B4B9AD1,
	0x01014041, 0x1F1FDBC4, 0xE0E0D838, 0xD6D661B7, 0x8E8E2FA1, 0xDFDF2BF4,
	0xCBCB3AF1, 0x3B3BF6CD, 0xE7E71DFA, 0x8585E560, 0x54544115, 0x868625A3,
	0x838360E3, 0xBABA16AC, 0x7575295C, 0x929234A6, 0x6E6EF799, 0xD0D0E434,
	0x6868721A, 0x55550154, 0xB6B619AF, 0x4E4EDF91, 0xC8C8FA32, 0xC0C0F030,
	0xD7D721F6, 0x3232BC8E, 0xC6C675B3, 0x8F8F6FE0, 0x7474691D, 0xDBDB2EF5,
	0x8B8B6AE1, 0xB8B8962E, 0x0A0A8A80, 0x9999FE67, 0x2B2BE2C9, 0x8181E061,
	0x0303C0C3, 0xA4A48D29, 0x8C8CAF23, 0xAEAE07A9, 0x3434390D, 0x4D4D1F52,
	0x3939764F, 0xBDBDD36E, 0x575781D6, 0x6F6FB7D8, 0xDCDCEB37, 0x15155144,
	0x7B7BA6DD, 0xF7F709FE, 0x3A3AB68C, 0xBCBC932F, 0x0C0C0F03, 0xFFFF03FC,
	0xA9A9C26B, 0xC9C9BA73, 0xB5B5D96C, 0xB1B1DC6D, 0x6D6D375A, 0x45451550,
	0x3636B98F, 0x6C6C771B, 0xBEBE13AD, 0x4A4ADA90, 0xEEEE57B9, 0x7777A9DE,
	0xF2F24CBE, 0xFDFD837E, 0x44445511, 0x6767BDDA, 0x71712C5D, 0x05054540,
	0x7C7C631F, 0x40405010, 0x6969325B, 0x6363B8DB, 0x2828220A, 0x0707C5C2,
	0xC4C4F531, 0x2222A88A, 0x969631A7, 0x3737F9CE, 0xEDED977A, 0xF6F649BF,
	0xB4B4992D, 0xD1D1A475, 0x434390D3, 0x48485A12, 0xE2E258BA, 0x979771E6,
	0xD2D264B6, 0xC2C270B2, 0x2626AD8B, 0xA5A5CD68, 0x5E5ECB95, 0x2929624B,
	0x30303C0C, 0x5A5ACE94, 0xDDDDAB76, 0xF9F9867F, 0x9595F164, 0xE6E65DBB,
	0xC7C735F2, 0x24242D09, 0x1717D1C6, 0xB9B9D66F, 0x1B1BDEC5, 0x12129486,
	0x60607818, 0xC3C330F3, 0xF5F5897C, 0xB3B35CEF, 0xE8E8D23A, 0x7373ACDF,
	0x3535794C, 0x8080A020, 0xE5E59D78, 0xBBBB56ED, 0x7D7D235E, 0xF8F8C63E,
	0x5F5F8BD4, 0x2F2FE7C8, 0xE4E4DD39, 0x21216849,
}

var sm4_sbox_t3 = [256]uint32{
	0xD55B5B8E, 0x924242D0, 0xEAA7A74D, 0xFDFBFB06, 0xCF3333FC, 0xE2878765,
	0x3DF4F4C9, 0xB5DEDE6B, 0x1658584E, 0xB4DADA6E, 0x14505044, 0xC10B0BCA,
	0x28A0A088, 0xF8EFEF17, 0x2CB0B09C, 0x05141411, 0x2BACAC87, 0x669D9DFB,
	0x986A6AF2, 0x77D9D9AE, 0x2AA8A882, 0xBCFAFA46, 0x04101014, 0xC00F0FCF,
	0xA8AAAA02, 0x45111154, 0x134C4C5F, 0x269898BE, 0x4825256D, 0x841A1A9E,
	0x0618181E, 0x9B6666FD, 0x9E7272EC, 0x4309094A, 0x51414110, 0xF7D3D324,
	0x934646D5, 0xECBFBF53, 0x9A6262F8, 0x7BE9E992, 0x33CCCCFF, 0x55515104,
	0x0B2C2C27, 0x420D0D4F, 0xEEB7B759, 0xCC3F3FF3, 0xAEB2B21C, 0x638989EA,
	0xE7939374, 0xB1CECE7F, 0x1C70706C, 0xABA6A60D, 0xCA2727ED, 0x08202028,
	0xEBA3A348, 0x975656C1, 0x82020280, 0xDC7F7FA3, 0x965252C4, 0xF9EBEB12,
	0x74D5D5A1, 0x8D3E3EB3, 0x3FFCFCC3, 0xA49A9A3E, 0x461D1D5B, 0x071C1C1B,
	0xA59E9E3B, 0xFFF3F30C, 0xF0CFCF3F, 0x72CDCDBF, 0x175C5C4B, 0xB8EAEA52,
	0x810E0E8F, 0x5865653D, 0x3CF0F0CC, 0x1964647D, 0xE59B9B7E, 0x87161691,
	0x4E3D3D73, 0xAAA2A208, 0x69A1A1C8, 0x6AADADC7, 0x83060685, 0xB0CACA7A,
	0x70C5C5B5, 0x659191F4, 0xD96B6BB2, 0x892E2EA7, 0xFBE3E318, 0xE8AFAF47,
	0x0F3C3C33, 0x4A2D2D67, 0x71C1C1B0, 0x5759590E, 0x9F7676E9, 0x35D4D4E1,
	0x1E787866, 0x249090B4, 0x0E383836, 0x5F797926, 0x628D8DEF, 0x59616138,
	0xD2474795, 0xA08A8A2A, 0x259494B1, 0x228888AA, 0x7DF1F18C, 0x3BECECD7,
	0x01040405, 0x218484A5, 0x79E1E198, 0x851E1E9B, 0xD7535384, 0x00000000,
	0x4719195E, 0x565D5D0B, 0x9D7E7EE3, 0xD04F4F9F, 0x279C9CBB, 0x5349491A,
	0x4D31317C, 0x36D8D8EE, 0x0208080A, 0xE49F9F7B, 0xA2828220, 0xC71313D4,
	0xCB2323E8, 0x9C7A7AE6, 0xE9ABAB42, 0xBDFEFE43, 0x882A2AA2, 0xD14B4B9A,
	0x41010140, 0xC41F1FDB, 0x38E0E0D8, 0xB7D6D661, 0xA18E8E2F, 0xF4DFDF2B,
	0xF1CBCB3A, 0xCD3B3BF6, 0xFAE7E71D, 0x608585E5, 0x15545441, 0xA3868625,
	0xE3838360, 0xACBABA16, 0x5C757529, 0xA6929234, 0x996E6EF7, 0x34D0D0E4,
	0x1A686872, 0x54555501, 0xAFB6B619, 0x914E4EDF, 0x32C8C8FA, 0x30C0C0F0,
	0xF6D7D721, 0x8E3232BC, 0xB3C6C675, 0xE08F8F6F, 0x1D747469, 0xF5DBDB2E,
	0xE18B8B6A, 0x2EB8B896, 0x800A0A8A, 0x679999FE, 0xC92B2BE2, 0x618181E0,
	0xC30303C0, 0x29A4A48D, 0x238C8CAF, 0xA9AEAE07, 0x0D343439, 0x524D4D1F,
	0x4F393976, 0x6EBDBDD3, 0xD6575781, 0xD86F6FB7, 0x37DCDCEB, 0x44151551,
	0xDD7B7BA6, 0xFEF7F709, 0x8C3A3AB6, 0x2FBCBC93, 0x030C0C0F, 0xFCFFFF03,
	0x6BA9A9C2, 0x73C9C9BA, 0x6CB5B5D9, 0x6DB1B1DC, 0x5A6D6D37, 0x50454515,
	0x8F3636B9, 0x1B6C6C77, 0xADBEBE13, 0x904A4ADA, 0xB9EEEE57, 0xDE7777A9,
	0xBEF2F24C, 0x7EFDFD83, 0x11444455, 0xDA6767BD, 0x5D71712C, 0x40050545,
	0x1F7C7C63, 0x10404050, 0x5B696932, 0xDB6363B8, 0x0A282822, 0xC20707C5,
	0x31C4C4F5, 0x8A2222A8, 0xA7969631, 0xCE3737F9, 0x7AEDED97, 0xBFF6F649,
	0x2DB4B499, 0x75D1D1A4, 0xD3434390, 0x1248485A, 0xBAE2E258, 0xE6979771,
	0xB6D2D264, 0xB2C2C270, 0x8B2626AD, 0x68A5A5CD, 0x955E5ECB, 0x4B292962,
	0x0C30303C, 0x945A5ACE, 0x76DDDDAB, 0x7FF9F986, 0x649595F1, 0xBBE6E65D,
	0xF2C7C735, 0x0924242D, 0xC61717D1, 0x6FB9B9D6, 0xC51B1BDE, 0x86121294,
	0x18606078, 0xF3C3C330, 0x7CF5F589, 0xEFB3B35C, 0x3AE8E8D2, 0xDF7373AC,
	0x4C353579, 0x208080A0, 0x78E5E59D, 0xEDBBBB56, 0x5E7D7D23, 0x3EF8F8C6,
	0xD45F5F8B, 0xC82F2FE7, 0x39E4E4DD, 0x49212168,
}

var sm4_ck = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

var sm4_fk = [4]uint32{
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
}

const SM4_KeySize = 16

// Encrypt one block from src into dst, using the expanded key xk.
func sm4_encryptBlockGo(xk *[sm4_rounds]uint32, dst, src []byte) {
	_ = src[15] // early bounds check

	var b0, b1, b2, b3 uint32
	b0 = binary.BigEndian.Uint32(src[0:4])
	b1 = binary.BigEndian.Uint32(src[4:8])
	b2 = binary.BigEndian.Uint32(src[8:12])
	b3 = binary.BigEndian.Uint32(src[12:16])

	// First round uses s-box directly and T transformation.
	b0 ^= sm4_t(b1 ^ b2 ^ b3 ^ xk[0])
	b1 ^= sm4_t(b2 ^ b3 ^ b0 ^ xk[1])
	b2 ^= sm4_t(b3 ^ b0 ^ b1 ^ xk[2])
	b3 ^= sm4_t(b0 ^ b1 ^ b2 ^ xk[3])

	// Middle rounds (unroll loop) uses precomputed tables.
	b0 ^= sm4_precompute_t(b1 ^ b2 ^ b3 ^ xk[4])
	b1 ^= sm4_precompute_t(b2 ^ b3 ^ b0 ^ xk[5])
	b2 ^= sm4_precompute_t(b3 ^ b0 ^ b1 ^ xk[6])
	b3 ^= sm4_precompute_t(b0 ^ b1 ^ b2 ^ xk[7])

	b0 ^= sm4_precompute_t(b1 ^ b2 ^ b3 ^ xk[8])
	b1 ^= sm4_precompute_t(b2 ^ b3 ^ b0 ^ xk[9])
	b2 ^= sm4_precompute_t(b3 ^ b0 ^ b1 ^ xk[10])
	b3 ^= sm4_precompute_t(b0 ^ b1 ^ b2 ^ xk[11])

	b0 ^= sm4_precompute_t(b1 ^ b2 ^ b3 ^ xk[12])
	b1 ^= sm4_precompute_t(b2 ^ b3 ^ b0 ^ xk[13])
	b2 ^= sm4_precompute_t(b3 ^ b0 ^ b1 ^ xk[14])
	b3 ^= sm4_precompute_t(b0 ^ b1 ^ b2 ^ xk[15])

	b0 ^= sm4_precompute_t(b1 ^ b2 ^ b3 ^ xk[16])
	b1 ^= sm4_precompute_t(b2 ^ b3 ^ b0 ^ xk[17])
	b2 ^= sm4_precompute_t(b3 ^ b0 ^ b1 ^ xk[18])
	b3 ^= sm4_precompute_t(b0 ^ b1 ^ b2 ^ xk[19])

	b0 ^= sm4_precompute_t(b1 ^ b2 ^ b3 ^ xk[20])
	b1 ^= sm4_precompute_t(b2 ^ b3 ^ b0 ^ xk[21])
	b2 ^= sm4_precompute_t(b3 ^ b0 ^ b1 ^ xk[22])
	b3 ^= sm4_precompute_t(b0 ^ b1 ^ b2 ^ xk[23])

	b0 ^= sm4_precompute_t(b1 ^ b2 ^ b3 ^ xk[24])
	b1 ^= sm4_precompute_t(b2 ^ b3 ^ b0 ^ xk[25])
	b2 ^= sm4_precompute_t(b3 ^ b0 ^ b1 ^ xk[26])
	b3 ^= sm4_precompute_t(b0 ^ b1 ^ b2 ^ xk[27])

	// Last round uses s-box directly and and T transformation to produce output.
	b0 ^= sm4_t(b1 ^ b2 ^ b3 ^ xk[28])
	b1 ^= sm4_t(b2 ^ b3 ^ b0 ^ xk[29])
	b2 ^= sm4_t(b3 ^ b0 ^ b1 ^ xk[30])
	b3 ^= sm4_t(b0 ^ b1 ^ b2 ^ xk[31])

	_ = dst[15] // early bounds check
	binary.BigEndian.PutUint32(dst[0:4], b3)
	binary.BigEndian.PutUint32(dst[4:8], b2)
	binary.BigEndian.PutUint32(dst[8:12], b1)
	binary.BigEndian.PutUint32(dst[12:16], b0)
}

// Key expansion algorithm.
func sm4_expandKeyGo(key []byte, enc, dec *[sm4_rounds]uint32) {
	// Encryption key setup.
	key = key[:SM4_KeySize]
	var b0, b1, b2, b3 uint32
	b0 = binary.BigEndian.Uint32(key[:4]) ^ sm4_fk[0]
	b1 = binary.BigEndian.Uint32(key[4:8]) ^ sm4_fk[1]
	b2 = binary.BigEndian.Uint32(key[8:12]) ^ sm4_fk[2]
	b3 = binary.BigEndian.Uint32(key[12:16]) ^ sm4_fk[3]

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[0])
	enc[0], dec[31] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[1])
	enc[1], dec[30] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[2])
	enc[2], dec[29] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[3])
	enc[3], dec[28] = b3, b3

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[4])
	enc[4], dec[27] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[5])
	enc[5], dec[26] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[6])
	enc[6], dec[25] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[7])
	enc[7], dec[24] = b3, b3

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[8])
	enc[8], dec[23] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[9])
	enc[9], dec[22] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[10])
	enc[10], dec[21] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[11])
	enc[11], dec[20] = b3, b3

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[12])
	enc[12], dec[19] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[13])
	enc[13], dec[18] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[14])
	enc[14], dec[17] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[15])
	enc[15], dec[16] = b3, b3

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[16])
	enc[16], dec[15] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[17])
	enc[17], dec[14] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[18])
	enc[18], dec[13] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[19])
	enc[19], dec[12] = b3, b3

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[20])
	enc[20], dec[11] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[21])
	enc[21], dec[10] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[22])
	enc[22], dec[9] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[23])
	enc[23], dec[8] = b3, b3

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[24])
	enc[24], dec[7] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[25])
	enc[25], dec[6] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[26])
	enc[26], dec[5] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[27])
	enc[27], dec[4] = b3, b3

	b0 = b0 ^ sm4_t2(b1^b2^b3^sm4_ck[28])
	enc[28], dec[3] = b0, b0
	b1 = b1 ^ sm4_t2(b2^b3^b0^sm4_ck[29])
	enc[29], dec[2] = b1, b1
	b2 = b2 ^ sm4_t2(b3^b0^b1^sm4_ck[30])
	enc[30], dec[1] = b2, b2
	b3 = b3 ^ sm4_t2(b0^b1^b2^sm4_ck[31])
	enc[31], dec[0] = b3, b3
}

// T
func sm4_t(in uint32) uint32 {
	var b uint32

	b = uint32(sm4_sbox[in&0xff])
	b |= uint32(sm4_sbox[in>>8&0xff]) << 8
	b |= uint32(sm4_sbox[in>>16&0xff]) << 16
	b |= uint32(sm4_sbox[in>>24&0xff]) << 24

	// L
	return b ^ (b<<2 | b>>30) ^ (b<<10 | b>>22) ^ (b<<18 | b>>14) ^ (b<<24 | b>>8)
}

// T'
func sm4_t2(in uint32) uint32 {
	var b uint32

	b = uint32(sm4_sbox[in&0xff])
	b |= uint32(sm4_sbox[in>>8&0xff]) << 8
	b |= uint32(sm4_sbox[in>>16&0xff]) << 16
	b |= uint32(sm4_sbox[in>>24&0xff]) << 24

	// L2
	return b ^ (b<<13 | b>>19) ^ (b<<23 | b>>9)
}

func sm4_precompute_t(in uint32) uint32 {
	return sm4_sbox_t0[in>>24&0xff] ^
		sm4_sbox_t1[in>>16&0xff] ^
		sm4_sbox_t2[in>>8&0xff] ^
		sm4_sbox_t3[in&0xff]
}

// newCipher calls the newCipherGeneric function
// directly. Platforms with hardware accelerated
// implementations of SM4 should implement their
// own version of newCipher (which may then call
// newCipherGeneric if needed).
func newCipher(key []byte) (cipher.Block, error) {
	return newCipherGeneric(key)
}

// BlockSize the sm4 block size in bytes.
const SM4_BlockSize = 16

const sm4_rounds = 32

// A cipher is an instance of SM4 encryption using a particular key.
type sm4Cipher struct {
	enc [sm4_rounds]uint32
	dec [sm4_rounds]uint32
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the SM4 key,
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, fmt.Errorf("sm4: invalid key size %d", k)
	case 16:
		break
	}
	return newCipher(key)
}

// newCipher creates and returns a new cipher.Block
// implemented in pure Go.
func newCipherGeneric(key []byte) (cipher.Block, error) {
	c := &sm4Cipher{}
	sm4_expandKeyGo(key, &c.enc, &c.dec)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int { return SM4_BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < SM4_BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < SM4_BlockSize {
		panic("sm4: output not full block")
	}
	if InexactOverlap(dst[:SM4_BlockSize], src[:SM4_BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	sm4_encryptBlockGo(&c.enc, dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < SM4_BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < SM4_BlockSize {
		panic("sm4: output not full block")
	}
	if InexactOverlap(dst[:SM4_BlockSize], src[:SM4_BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	sm4_encryptBlockGo(&c.dec, dst, src)
}

const (
	sm4_ccmBlockSize         = 16
	sm4_ccmTagSize           = 16
	sm4_ccmMinimumTagSize    = 4
	sm4_ccmStandardNonceSize = 12
)

// ccmAble is an interface implemented by ciphers that have a specific optimized
// implementation of CCM.
type sm4_ccmAble interface {
	NewCCM(nonceSize, tagSize int) (cipher.AEAD, error)
}

type sm4_ccm struct {
	cipher    cipher.Block
	nonceSize int
	tagSize   int
}

func (c *sm4_ccm) NonceSize() int {
	return c.nonceSize
}

func (c *sm4_ccm) Overhead() int {
	return c.tagSize
}

func (c *sm4_ccm) MaxLength() int {
	return sm4_maxlen(15-c.NonceSize(), c.Overhead())
}

func sm4_maxlen(L, tagsize int) int {
	max := (uint64(1) << (8 * L)) - 1
	if m64 := uint64(math.MaxInt64) - uint64(tagsize); L > 8 || max > m64 {
		max = m64 // The maximum lentgh on a 64bit arch
	}
	if max != uint64(int(max)) {
		return math.MaxInt32 - tagsize // We have only 32bit int's
	}
	return int(max)
}

// NewCCM returns the given 128-bit, block cipher wrapped in CCM
// with the standard nonce length.
func NewCCM(cipher cipher.Block) (cipher.AEAD, error) {
	return NewCCMWithNonceAndTagSize(cipher, sm4_ccmStandardNonceSize, sm4_ccmTagSize)
}

// NewCCMWithNonceSize returns the given 128-bit, block cipher wrapped in CCM,
// which accepts nonces of the given length. The length must not
// be zero.
func NewCCMWithNonceSize(cipher cipher.Block, size int) (cipher.AEAD, error) {
	return NewCCMWithNonceAndTagSize(cipher, size, sm4_ccmTagSize)
}

// NewCCMWithTagSize returns the given 128-bit, block cipher wrapped in CCM,
// which generates tags with the given length.
//
// Tag sizes between 8 and 16 bytes are allowed.
func NewCCMWithTagSize(cipher cipher.Block, tagSize int) (cipher.AEAD, error) {
	return NewCCMWithNonceAndTagSize(cipher, sm4_ccmStandardNonceSize, tagSize)
}

// https://tools.ietf.org/html/rfc3610
func NewCCMWithNonceAndTagSize(cipher cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if tagSize < sm4_ccmMinimumTagSize || tagSize > sm4_ccmBlockSize || tagSize&1 != 0 {
		return nil, errors.New("cipher: incorrect tag size given to CCM")
	}

	if nonceSize <= 0 {
		return nil, errors.New("cipher: the nonce can't have zero length, or the security of the key will be immediately compromised")
	}

	lenSize := 15 - nonceSize
	if lenSize < 2 || lenSize > 8 {
		return nil, errors.New("cipher: invalid ccm nounce size, should be in [7,13]")
	}

	if cipher, ok := cipher.(sm4_ccmAble); ok {
		return cipher.NewCCM(nonceSize, tagSize)
	}

	if cipher.BlockSize() != sm4_ccmBlockSize {
		return nil, errors.New("cipher: NewCCM requires 128-bit block cipher")
	}

	c := &sm4_ccm{cipher: cipher, nonceSize: nonceSize, tagSize: tagSize}

	return c, nil
}

// https://tools.ietf.org/html/rfc3610
func (c *sm4_ccm) deriveCounter(counter *[sm4_ccmBlockSize]byte, nonce []byte) {
	counter[0] = byte(14 - c.nonceSize)
	copy(counter[1:], nonce)
}

func (c *sm4_ccm) cmac(out, data []byte) {
	for len(data) >= sm4_ccmBlockSize {
		XORBytes(out, out, data)
		c.cipher.Encrypt(out, out)
		data = data[sm4_ccmBlockSize:]
	}
	if len(data) > 0 {
		var block [sm4_ccmBlockSize]byte
		copy(block[:], data)
		XORBytes(out, out, data)
		c.cipher.Encrypt(out, out)
	}
}

// https://tools.ietf.org/html/rfc3610 2.2. Authentication
func (c *sm4_ccm) auth(nonce, plaintext, additionalData []byte, tagMask *[sm4_ccmBlockSize]byte) []byte {
	var out [sm4_ccmTagSize]byte
	if len(additionalData) > 0 {
		out[0] = 1 << 6 // 64*Adata
	}
	out[0] |= byte(c.tagSize-2) << 2 // M' = ((tagSize - 2) / 2)*8
	out[0] |= byte(14 - c.nonceSize) // L'
	binary.BigEndian.PutUint64(out[sm4_ccmBlockSize-8:], uint64(len(plaintext)))
	copy(out[1:], nonce)
	// B0
	c.cipher.Encrypt(out[:], out[:])

	var block [sm4_ccmBlockSize]byte
	if n := uint64(len(additionalData)); n > 0 {
		// First adata block includes adata length
		i := 2
		if n <= 0xfeff { // l(a) < (2^16 - 2^8)
			binary.BigEndian.PutUint16(block[:i], uint16(n))
		} else {
			block[0] = 0xff
			// If (2^16 - 2^8) <= l(a) < 2^32, then the length field is encoded as
			// six octets consisting of the octets 0xff, 0xfe, and four octets
			// encoding l(a) in most-significant-byte-first order.
			if n < uint64(1<<32) {
				block[1] = 0xfe
				i = 2 + 4
				binary.BigEndian.PutUint32(block[2:i], uint32(n))
			} else {
				block[1] = 0xff
				// If 2^32 <= l(a) < 2^64, then the length field is encoded as ten
				// octets consisting of the octets 0xff, 0xff, and eight octets encoding
				// l(a) in most-significant-byte-first order.
				i = 2 + 8
				binary.BigEndian.PutUint64(block[2:i], uint64(n))
			}
		}
		i = copy(block[i:], additionalData) // first block start with additional data length
		c.cmac(out[:], block[:])
		c.cmac(out[:], additionalData[i:])
	}
	if len(plaintext) > 0 {
		c.cmac(out[:], plaintext)
	}
	XORBytes(out[:], out[:], tagMask[:])
	return out[:c.tagSize]
}

func (c *sm4_ccm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("cipher: incorrect nonce length given to CCM")
	}
	if uint64(len(plaintext)) > uint64(c.MaxLength()) {
		panic("cipher: message too large for CCM")
	}
	ret, out := SliceForAppend(dst, len(plaintext)+c.tagSize)
	if InexactOverlap(out, plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	var counter, tagMask [sm4_ccmBlockSize]byte
	c.deriveCounter(&counter, nonce)
	c.cipher.Encrypt(tagMask[:], counter[:])

	counter[len(counter)-1] |= 1
	ctr := cipher.NewCTR(c.cipher, counter[:])
	ctr.XORKeyStream(out, plaintext)

	tag := c.auth(nonce, plaintext, data, &tagMask)
	copy(out[len(plaintext):], tag)

	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (c *sm4_ccm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		panic("cipher: incorrect nonce length given to CCM")
	}
	// Sanity check to prevent the authentication from always succeeding if an implementation
	// leaves tagSize uninitialized, for example.
	if c.tagSize < sm4_ccmMinimumTagSize {
		panic("cipher: incorrect CCM tag size")
	}

	if len(ciphertext) < c.tagSize {
		return nil, errOpen
	}

	if len(ciphertext) > c.MaxLength()+c.Overhead() {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-c.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-c.tagSize]

	var counter, tagMask [sm4_ccmBlockSize]byte
	c.deriveCounter(&counter, nonce)
	c.cipher.Encrypt(tagMask[:], counter[:])

	ret, out := SliceForAppend(dst, len(ciphertext))
	if InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	counter[len(counter)-1] |= 1
	ctr := cipher.NewCTR(c.cipher, counter[:])
	ctr.XORKeyStream(out, ciphertext)
	expectedTag := c.auth(nonce, out, data, &tagMask)
	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		// The AESNI code decrypts and authenticates concurrently, and
		// so overwrites dst in the event of a tag mismatch. That
		// behavior is mimicked here in order to be consistent across
		// platforms.
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}

// Padding interface represents a padding scheme
type Padding interface {
	BlockSize() int
	Pad(src []byte) []byte
	Unpad(src []byte) ([]byte, error)
}

func NewPKCS7Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return pkcs7Padding(blockSize)
}

func NewANSIX923Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return ansiX923Padding(blockSize)
}

func NewISO9797M2Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return iso9797M2Padding(blockSize)
}

// https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
type pkcs7Padding uint

func (pad pkcs7Padding) BlockSize() int {
	return int(pad)
}

func (pad pkcs7Padding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	ret, out := SliceForAppend(src, overhead)
	for i := 0; i < overhead; i++ {
		out[i] = byte(overhead)
	}
	return ret
}

// Unpad decrypted plaintext, non-constant-time
func (pad pkcs7Padding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}
	paddedLen := src[srcLen-1]
	if paddedLen == 0 || int(paddedLen) > pad.BlockSize() {
		return nil, errors.New("padding: invalid padding byte/length")
	}
	for _, b := range src[srcLen-int(paddedLen) : srcLen-1] {
		if b != paddedLen {
			return nil, errors.New("padding: inconsistent padding bytes")
		}
	}
	return src[:srcLen-int(paddedLen)], nil
}

// Add a single bit with value 1 to the end of the data.
// Then if necessary add bits with value 0 to the end of the data until the padded data is a multiple of n.
//
// https://en.wikipedia.org/wiki/ISO/IEC_9797-1
// also GB/T 17964-2021 C.2 Padding method 2
type iso9797M2Padding uint

func (pad iso9797M2Padding) BlockSize() int {
	return int(pad)
}

func (pad iso9797M2Padding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	ret, out := SliceForAppend(src, overhead)
	out[0] = 0x80
	for i := 1; i < overhead; i++ {
		out[i] = 0
	}
	return ret
}

// Unpad decrypted plaintext, non-constant-time
func (pad iso9797M2Padding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}
	padStart := -1

	for i, b := range src[srcLen-pad.BlockSize() : srcLen] {
		if b == 0x80 {
			padStart = i
		} else if b != 0 && padStart >= 0 {
			padStart = -1
		}
	}
	if padStart >= 0 {
		return src[:srcLen-pad.BlockSize()+padStart], nil
	}
	return src, nil
}

// https://www.ibm.com/docs/en/linux-on-systems?topic=processes-ansi-x923-cipher-block-chaining
type ansiX923Padding uint

func (pad ansiX923Padding) BlockSize() int {
	return int(pad)
}

func (pad ansiX923Padding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	ret, out := SliceForAppend(src, overhead)
	out[overhead-1] = byte(overhead)
	for i := 0; i < overhead-1; i++ {
		out[i] = 0
	}
	return ret
}

// Unpad decrypted plaintext, non-constant-time
func (pad ansiX923Padding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}
	paddedLen := src[srcLen-1]
	if paddedLen == 0 || int(paddedLen) > pad.BlockSize() {
		return nil, errors.New("padding: invalid padding length")
	}
	for _, b := range src[srcLen-int(paddedLen) : srcLen-1] {
		if b != 0 {
			return nil, errors.New("padding: invalid padding bytes")
		}
	}
	return src[:srcLen-int(paddedLen)], nil
}
