//! `clock_gettime` through the vDSO for the static musl build. musl finds the vDSO's functions only
//! through its DT_HASH table, and the arm64 vDSO of recent kernels has DT_GNU_HASH alone, so every
//! clock read — tokio's timers, hyper's, the access log: about eight per request — became a system
//! call. The definition below takes the place of musl's (a weak symbol there) for the whole binary:
//! it looks the vDSO function up once, through DT_GNU_HASH or DT_HASH, and calls the system when
//! there is none or it declines. It allocates nothing: the allocator reads the clock too.

use std::sync::atomic::{AtomicUsize, Ordering};

type ClockGettime = unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int;

/// 0: not looked up yet; 1: the vDSO has no such function; otherwise its address.
static FUNCTION: AtomicUsize = AtomicUsize::new(0);

/// Replaces musl's `clock_gettime`.
///
/// # Safety
/// As `clock_gettime(3)`: `ts` points to a `timespec` that may be written.
#[cfg(target_env = "musl")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clock: libc::clockid_t, ts: *mut libc::timespec) -> libc::c_int {
    if let Some(function) = function()
        // SAFETY: the vDSO's clock_gettime, with the caller's arguments.
        && unsafe { function(clock, ts) } == 0
    {
        return 0;
    }
    // A clock the vDSO does not read (it answers -errno): the system sets errno.
    // SAFETY: the system call with the caller's arguments.
    unsafe { libc::syscall(libc::SYS_clock_gettime, clock, ts) as libc::c_int }
}

/// The vDSO's `clock_gettime`, looked up on first use.
fn function() -> Option<ClockGettime> {
    let mut address = FUNCTION.load(Ordering::Relaxed);
    if address == 0 {
        address = lookup().unwrap_or(1);
        // Threads that look up at once find the same address.
        FUNCTION.store(address, Ordering::Relaxed);
    }
    // SAFETY: a function of the vDSO with clock_gettime's signature (looked up by its name).
    (address > 1).then(|| unsafe { std::mem::transmute::<usize, ClockGettime>(address) })
}

#[cfg(target_arch = "aarch64")]
const NAME: &[u8] = b"__kernel_clock_gettime";
#[cfg(target_arch = "x86_64")]
const NAME: &[u8] = b"__vdso_clock_gettime";
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const NAME: &[u8] = b"";

fn lookup() -> Option<usize> {
    if NAME.is_empty() {
        return None;
    }
    // SAFETY: getauxval only reads the auxiliary vector.
    let base = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as usize;
    if base == 0 {
        return None;
    }
    // SAFETY: the kernel maps a complete ELF image at AT_SYSINFO_EHDR.
    unsafe { find(base, NAME) }
}

#[repr(C)]
struct Ehdr {
    ident: [u8; 16],
    kind: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
}

#[repr(C)]
struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[repr(C)]
struct Dyn {
    tag: i64,
    value: u64,
}

#[repr(C)]
struct Sym {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const STT_FUNC: u8 = 2;

/// The address of the function `name` in the ELF image mapped at `base` (as musl's `__vdsosym`
/// reads it: addresses relative to the first PT_LOAD, the dynamic section at its file offset).
///
/// # Safety
/// `base` is where a complete 64-bit ELF image is mapped.
unsafe fn find(base: usize, name: &[u8]) -> Option<usize> {
    // SAFETY (all reads): within the image, as its own headers and tables describe it.
    unsafe {
        let ehdr = &*(base as *const Ehdr);
        if ehdr.ident[..4] != *b"\x7fELF" || ehdr.ident[4] != 2 {
            return None;
        }
        let mut bias = None;
        let mut dynamic = None;
        for i in 0..usize::from(ehdr.phnum) {
            let phdr = &*((base + ehdr.phoff as usize + i * usize::from(ehdr.phentsize)) as *const Phdr);
            match phdr.kind {
                PT_LOAD if bias.is_none() => {
                    bias = Some(
                        base.wrapping_add(phdr.offset as usize)
                            .wrapping_sub(phdr.vaddr as usize),
                    );
                }
                PT_DYNAMIC => dynamic = Some((base + phdr.offset as usize) as *const Dyn),
                _ => {}
            }
        }
        let (bias, mut entry) = (bias?, dynamic?);
        let (mut strtab, mut symtab, mut hash, mut gnu_hash) = (0, 0, 0, 0);
        while (*entry).tag != DT_NULL {
            let at = bias.wrapping_add((*entry).value as usize);
            match (*entry).tag {
                DT_STRTAB => strtab = at,
                DT_SYMTAB => symtab = at,
                DT_HASH => hash = at,
                DT_GNU_HASH => gnu_hash = at,
                _ => {}
            }
            entry = entry.add(1);
        }
        if strtab == 0 || symtab == 0 {
            return None;
        }
        let symbol = |index: u32| -> Option<usize> {
            let sym = &*((symtab + index as usize * size_of::<Sym>()) as *const Sym);
            let found = sym.shndx != 0
                && sym.info & 0xf == STT_FUNC
                && std::ffi::CStr::from_ptr((strtab + sym.name as usize) as *const libc::c_char).to_bytes() == name;
            found.then(|| bias.wrapping_add(sym.value as usize))
        };
        if gnu_hash != 0 {
            let table = gnu_hash as *const u32;
            let (buckets, first, bloom_words) = (*table, *table.add(1), *table.add(2));
            if buckets == 0 {
                return None;
            }
            let hash = name
                .iter()
                .fold(5381u32, |h, c| h.wrapping_mul(33).wrapping_add(u32::from(*c)));
            // The bloom filter (64-bit words) comes before the buckets.
            let bucket = table.add(4 + 2 * bloom_words as usize);
            let chain = bucket.add(buckets as usize);
            let mut index = *bucket.add((hash % buckets) as usize);
            if index < first {
                return None;
            }
            loop {
                let value = *chain.add((index - first) as usize);
                if value | 1 == hash | 1
                    && let Some(address) = symbol(index)
                {
                    return Some(address);
                }
                if value & 1 != 0 {
                    return None;
                }
                index += 1;
            }
        }
        if hash != 0 {
            let table = hash as *const u32;
            let buckets = *table;
            if buckets == 0 {
                return None;
            }
            let mut h = 0u32;
            for c in name {
                h = (h << 4).wrapping_add(u32::from(*c));
                let g = h & 0xf000_0000;
                if g != 0 {
                    h ^= g >> 24;
                }
                h &= !g;
            }
            let chain = table.add(2 + buckets as usize);
            let mut index = *table.add(2 + (h % buckets) as usize);
            while index != 0 {
                if let Some(address) = symbol(index) {
                    return Some(address);
                }
                index = *chain.add(index as usize);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now(read: impl Fn(*mut libc::timespec) -> libc::c_int) -> std::time::Duration {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        assert_eq!(read(&mut ts), 0);
        std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn the_vdso_function_reads_the_clocks_the_system_reads() {
        let function = function().expect("the vDSO's clock_gettime");
        for clock in [libc::CLOCK_MONOTONIC, libc::CLOCK_REALTIME] {
            // SAFETY: the system call with a valid timespec.
            let system = now(|ts| unsafe { libc::syscall(libc::SYS_clock_gettime, clock, ts) as libc::c_int });
            // SAFETY: the vDSO function with a valid timespec.
            let vdso = now(|ts| unsafe { function(clock, ts) });
            assert!(
                vdso >= system && vdso - system < std::time::Duration::from_secs(1),
                "clock {clock}"
            );
        }
    }

    #[test]
    fn a_name_the_vdso_does_not_have() {
        // SAFETY: as lookup().
        let base = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as usize;
        if base != 0 {
            // SAFETY: the kernel's image.
            assert_eq!(unsafe { find(base, b"__kernel_no_such_function") }, None);
        }
    }
}
