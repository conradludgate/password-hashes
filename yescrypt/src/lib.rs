#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(
    //clippy::cast_lossless,
    //clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    //clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    //missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
// Temporary lint overrides while C code is being translated
#![allow(
    clippy::too_many_arguments,
    non_camel_case_types,
    non_snake_case,
    unsafe_op_in_unsafe_fn
)]

// Adapted from the yescrypt reference implementation available at:
// <https://github.com/openwall/yescrypt>
//
// Relicensed from the BSD-2-Clause license to Apache 2.0+MIT with permission:
// <https://github.com/openwall/yescrypt/issues/7>

extern crate alloc;

mod common;
mod salsa20;
mod sha256;

use crate::{
    common::{blkcpy, blkxor, integerify, le32dec, le32enc, prev_power_of_two, wrap},
    sha256::{HMAC_SHA256_Buf, PBKDF2_SHA256, SHA256_Buf},
};
use alloc::{vec, vec::Vec};
use core::{
    mem::{self, size_of},
    ptr,
};
use libc::{free, malloc, memcpy};

#[derive(Copy, Clone)]
#[repr(C)]
struct Local {
    pub base: *mut u32,
    pub aligned: *mut u32,
    pub base_size: usize,
    pub aligned_size: usize,
}

type Region = Local;
type Shared = Region;
type Flags = u32;

#[derive(Copy, Clone)]
#[repr(C)]
struct Params {
    pub flags: Flags,
    pub N: u64,
    pub r: u32,
    pub p: u32,
    pub t: u32,
    pub g: u32,
    pub NROM: u64,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct PwxformCtx {
    pub S: *mut u32,
    pub S0: *mut [u32; 2],
    pub S1: *mut [u32; 2],
    pub S2: *mut [u32; 2],
    pub w: usize,
}

/// yescrypt Key Derivation Function (KDF)
pub fn yescrypt_kdf(
    passwd: &[u8],
    salt: &[u8],
    flags: u32,
    n: u64,
    r: u32,
    p: u32,
    t: u32,
    g: u32,
    dstlen: usize,
) -> Vec<u8> {
    let params = Params {
        flags,
        N: n,
        r,
        p,
        t,
        g,
        NROM: 0,
    };

    let mut local: Local = unsafe { mem::zeroed() };
    unsafe {
        yescrypt_init_local(&mut local);
    }

    let mut dst = vec![0u8; dstlen];

    unsafe {
        yescrypt_kdf_inner(
            ptr::null(),
            &mut local,
            passwd.as_ptr(),
            passwd.len(),
            salt.as_ptr(),
            salt.len(),
            &params,
            dst.as_mut_ptr(),
            dstlen,
        )
    };
    dst
}

unsafe fn yescrypt_kdf_inner(
    shared: *const Shared,
    local: *mut Local,
    mut passwd: *const u8,
    mut passwdlen: usize,
    salt: *const u8,
    saltlen: usize,
    params: *const Params,
    buf: *mut u8,
    buflen: usize,
) -> libc::c_int {
    let flags: Flags = (*params).flags;
    let N: u64 = (*params).N;
    let r: u32 = (*params).r;
    let p: u32 = (*params).p;
    let t: u32 = (*params).t;
    let g: u32 = (*params).g;
    let NROM: u64 = (*params).NROM;
    let mut dk: [u8; 32] = [0; 32];
    if g != 0 {
        return -(1);
    }
    if flags & 0x2_u32 != 0
        && p >= 1_u32
        && N.wrapping_div(p as u64) >= 0x100_u64
        && N.wrapping_div(p as u64).wrapping_mul(r as u64) >= 0x20000_u64
    {
        let retval: libc::c_int = yescrypt_kdf_body(
            shared,
            local,
            passwd,
            passwdlen,
            salt,
            saltlen,
            flags | 0x10000000_u32,
            N >> 6,
            r,
            p,
            0_u32,
            NROM,
            dk.as_mut_ptr(),
            size_of::<[u8; 32]>(),
        );
        if retval != 0 {
            return retval;
        }
        passwd = dk.as_mut_ptr();
        passwdlen = size_of::<[u8; 32]>();
    }
    yescrypt_kdf_body(
        shared, local, passwd, passwdlen, salt, saltlen, flags, N, r, p, t, NROM, buf, buflen,
    )
}

unsafe fn yescrypt_init_local(local: *mut Local) -> libc::c_int {
    (*local).aligned = ptr::null_mut();
    (*local).base = (*local).aligned;
    (*local).aligned_size = 0_usize;
    (*local).base_size = (*local).aligned_size;
    0
}

unsafe fn yescrypt_kdf_body(
    shared: *const Shared,
    local: *mut Local,
    mut passwd: *const u8,
    mut passwdlen: usize,
    salt: *const u8,
    saltlen: usize,
    flags: Flags,
    N: u64,
    r: u32,
    p: u32,
    t: u32,
    NROM: u64,
    buf: *mut u8,
    buflen: usize,
) -> libc::c_int {
    let mut current_block: u64;
    let mut retval: libc::c_int = -(1);
    let mut V: *mut u32;
    let mut sha256: [u32; 8] = [0; 8];
    let mut dk: [u8; 32] = [0; 32];
    match flags & 0x3_u32 {
        0 => {
            if flags != 0 || t != 0 || NROM != 0 {
                current_block = 15162489974460950378;
            } else {
                current_block = 2868539653012386629;
            }
        }
        1 => {
            if flags != 1_u32 || NROM != 0 {
                current_block = 15162489974460950378;
            } else {
                current_block = 2868539653012386629;
            }
        }
        2 => {
            if flags != flags & (0x3 | 0x3fc | 0x10000 | 0x1000000 | 0x8000000 | 0x10000000) as u32
            {
                current_block = 15162489974460950378;
            } else if flags & 0x3fc_u32 == (0x4 | 0x10 | 0x20 | 0x80) as u32 {
                current_block = 2868539653012386629;
            } else {
                current_block = 15162489974460950378;
            }
        }
        _ => {
            current_block = 15162489974460950378;
        }
    }
    if current_block == 2868539653012386629
        && buflen <= (1usize << 32).wrapping_sub(1).wrapping_mul(32)
        && (r as u64).wrapping_mul(p as u64) < ((1) << 30) as u64
        && !(N & N.wrapping_sub(1_u64) != 0_u64 || N <= 1_u64 || r < 1_u32 || p < 1_u32)
        && !(r as u64
            > 18446744073709551615_u64
                .wrapping_div(128_u64)
                .wrapping_div(p as u64)
            || N > 18446744073709551615_u64
                .wrapping_div(128_u64)
                .wrapping_div(r as u64))
        && N <= 18446744073709551615_u64.wrapping_div((t as u64).wrapping_add(1_u64))
    {
        if flags & 0x2_u32 != 0 {
            if N.wrapping_div(p as u64) <= 1_u64
                || r < ((4 * 2 * 8 + 127) / 128) as u32
                || p as u64 > 18446744073709551615_u64.wrapping_div((3 * ((1) << 8) * 2 * 8) as u64)
                || p as u64 > 18446744073709551615_u64.wrapping_div(size_of::<PwxformCtx>() as u64)
            {
                current_block = 15162489974460950378;
            } else {
                current_block = 6009453772311597924;
            }
        } else {
            current_block = 6009453772311597924;
        }
        match current_block {
            15162489974460950378 => {}
            _ => {
                let mut VROM = ptr::null();
                if !shared.is_null() {
                    let expected_size = (128usize)
                        .wrapping_mul(r as usize)
                        .wrapping_mul(NROM as usize);
                    if NROM & NROM.wrapping_sub(1_u64) != 0_u64
                        || NROM <= 1_u64
                        || (*shared).aligned_size < expected_size
                    {
                        current_block = 15162489974460950378;
                    } else {
                        if flags & 0x1000000_u32 == 0 {
                            let tag: *mut u32 = (*shared).aligned.byte_add(expected_size).sub(48);
                            let tag1: u64 =
                                ((*tag.add(1) as u64) << 32).wrapping_add(*tag.add(0) as u64);
                            let tag2: u64 = ((*tag.add(3) as u64) << 32)
                                .wrapping_add(*tag.add(2) as libc::c_ulong);
                            if tag1 != 0x7470797263736579_u64 || tag2 != 0x687361684d4f522d_u64 {
                                current_block = 15162489974460950378;
                            } else {
                                current_block = 13472856163611868459;
                            }
                        } else {
                            current_block = 13472856163611868459;
                        }
                        match current_block {
                            15162489974460950378 => {}
                            _ => {
                                VROM = (*shared).aligned;
                                current_block = 14763689060501151050;
                            }
                        }
                    }
                } else if NROM != 0 {
                    current_block = 15162489974460950378;
                } else {
                    current_block = 14763689060501151050;
                }
                match current_block {
                    15162489974460950378 => {}
                    _ => {
                        let V_size = 128usize.wrapping_mul(r as usize).wrapping_mul(N as usize);
                        if flags & 0x1000000_u32 != 0 {
                            V = (*local).aligned;
                            if (*local).aligned_size < V_size {
                                if !((*local).base).is_null()
                                    || !((*local).aligned).is_null()
                                    || (*local).base_size != 0
                                    || (*local).aligned_size != 0
                                {
                                    current_block = 15162489974460950378;
                                } else {
                                    V = malloc(V_size) as *mut u32;
                                    if V.is_null() {
                                        return -(1);
                                    }
                                    (*local).aligned = V;
                                    (*local).base = (*local).aligned;
                                    (*local).aligned_size = V_size;
                                    (*local).base_size = (*local).aligned_size;
                                    current_block = 9853141518545631134;
                                }
                            } else {
                                current_block = 9853141518545631134;
                            }
                            match current_block {
                                15162489974460950378 => {}
                                _ => {
                                    if flags & 0x8000000_u32 != 0 {
                                        return -(2);
                                    }
                                    current_block = 7746103178988627676;
                                }
                            }
                        } else {
                            V = malloc(V_size) as *mut u32;
                            if V.is_null() {
                                return -(1);
                            }
                            current_block = 7746103178988627676;
                        }
                        match current_block {
                            15162489974460950378 => {}
                            _ => {
                                let B_size =
                                    128usize.wrapping_mul(r as usize).wrapping_mul(p as usize);
                                let B = malloc(B_size) as *mut u32;
                                if !B.is_null() {
                                    let XY = malloc(256usize.wrapping_mul(r as usize)) as *mut u32;
                                    if !XY.is_null() {
                                        let mut S = ptr::null_mut();
                                        let mut pwxform_ctx = ptr::null_mut();
                                        if flags & 0x2_u32 != 0 {
                                            S = malloc(
                                                (3usize * ((1usize) << 8usize) * 2usize * 8usize)
                                                    .wrapping_mul(p as usize),
                                            )
                                                as *mut u32;
                                            if S.is_null() {
                                                current_block = 4048828170348623652;
                                            } else {
                                                pwxform_ctx = malloc(
                                                    size_of::<PwxformCtx>()
                                                        .wrapping_mul(p as usize),
                                                )
                                                    as *mut PwxformCtx;
                                                if pwxform_ctx.is_null() {
                                                    current_block = 15241037615328978;
                                                } else {
                                                    current_block = 12381812505308290051;
                                                }
                                            }
                                        } else {
                                            current_block = 12381812505308290051;
                                        }
                                        if current_block == 12381812505308290051 {
                                            if flags != 0 {
                                                HMAC_SHA256_Buf(
                                                    b"yescrypt-prehash".as_ptr(),
                                                    (if flags & 0x10000000_u32 != 0 {
                                                        16
                                                    } else {
                                                        8
                                                    })
                                                        as usize,
                                                    passwd,
                                                    passwdlen,
                                                    sha256.as_mut_ptr() as *mut u8,
                                                );
                                                passwd = sha256.as_mut_ptr() as *mut u8;
                                                passwdlen = size_of::<[u32; 8]>();
                                            }
                                            PBKDF2_SHA256(
                                                passwd,
                                                passwdlen,
                                                salt,
                                                saltlen,
                                                1_u64,
                                                B as *mut u8,
                                                B_size,
                                            );
                                            if flags != 0 {
                                                blkcpy(
                                                    sha256.as_mut_ptr(),
                                                    B,
                                                    (size_of::<[u32; 8]>())
                                                        .wrapping_div(size_of::<u32>()),
                                                );
                                            }
                                            if flags & 0x2_u32 != 0 {
                                                for i in 0..p {
                                                    (*pwxform_ctx.add(i as usize)).S = S.add(
                                                        (i as u64).wrapping_mul(
                                                            ((3 * ((1) << 8) * 2 * 8) as u64)
                                                                .wrapping_div(
                                                                    size_of::<u32>() as u64
                                                                ),
                                                        )
                                                            as usize,
                                                    );
                                                }
                                                smix(
                                                    B,
                                                    r as usize,
                                                    N,
                                                    p,
                                                    t,
                                                    flags,
                                                    V,
                                                    NROM,
                                                    VROM,
                                                    XY,
                                                    pwxform_ctx,
                                                    sha256.as_mut_ptr() as *mut u8,
                                                );
                                            } else {
                                                for i in 0..p {
                                                    smix(
                                                        B.add(
                                                            (32usize)
                                                                .wrapping_mul(r as usize)
                                                                .wrapping_mul(i as usize),
                                                        ),
                                                        r as usize,
                                                        N,
                                                        1_u32,
                                                        t,
                                                        flags,
                                                        V,
                                                        NROM,
                                                        VROM,
                                                        XY,
                                                        ptr::null_mut(),
                                                        ptr::null_mut(),
                                                    );
                                                }
                                            }
                                            let mut dkp = buf;
                                            if flags != 0 && buflen < size_of::<[u8; 32]>() {
                                                PBKDF2_SHA256(
                                                    passwd,
                                                    passwdlen,
                                                    B as *mut u8,
                                                    B_size,
                                                    1_u64,
                                                    dk.as_mut_ptr(),
                                                    size_of::<[u8; 32]>(),
                                                );
                                                dkp = dk.as_mut_ptr();
                                            }
                                            PBKDF2_SHA256(
                                                passwd,
                                                passwdlen,
                                                B as *mut u8,
                                                B_size,
                                                1_u64,
                                                buf,
                                                buflen,
                                            );
                                            if flags != 0 && flags & 0x10000000_u32 == 0 {
                                                HMAC_SHA256_Buf(
                                                    dkp,
                                                    size_of::<[u8; 32]>(),
                                                    b"Client Key".as_ptr(),
                                                    10_usize,
                                                    sha256.as_mut_ptr() as *mut u8,
                                                );
                                                let mut clen: usize = buflen;
                                                if clen > size_of::<[u8; 32]>() {
                                                    clen = size_of::<[u8; 32]>();
                                                }
                                                SHA256_Buf(
                                                    sha256.as_mut_ptr() as *mut u8,
                                                    size_of::<[u32; 8]>(),
                                                    dk.as_mut_ptr(),
                                                );
                                                memcpy(
                                                    buf as *mut libc::c_void,
                                                    dk.as_mut_ptr() as *const libc::c_void,
                                                    clen,
                                                );
                                            }
                                            retval = 0;
                                            free(pwxform_ctx as *mut libc::c_void);
                                            current_block = 15241037615328978;
                                        }
                                        if current_block == 15241037615328978 {
                                            free(S as *mut libc::c_void);
                                        }
                                        free(XY as *mut libc::c_void);
                                    }
                                    free(B as *mut libc::c_void);
                                }
                                if flags & 0x1000000_u32 == 0 {
                                    free(V as *mut libc::c_void);
                                }
                                return retval;
                            }
                        }
                    }
                }
            }
        }
    }
    -(1)
}

unsafe fn pwxform(B: *mut u32, ctx: *mut PwxformCtx) {
    let X: *mut [[u32; 2]; 2] = B as *mut [[u32; 2]; 2];
    let S0: *mut [u32; 2] = (*ctx).S0;
    let S1: *mut [u32; 2] = (*ctx).S1;
    let S2: *mut [u32; 2] = (*ctx).S2;
    let mut w: usize = (*ctx).w;
    for i in 0..6 {
        for j in 0..4 {
            let mut xl: u32 = (*X.add(j))[0][0];
            let mut xh: u32 = (*X.add(j))[0][1];
            let p0 = S0.add(
                ((xl & ((((1) << 8) - 1) * 2 * 8) as u32) as u64)
                    .wrapping_div(size_of::<[u32; 2]>() as u64) as usize,
            );
            let p1 = S1.add(
                ((xh & ((((1) << 8) - 1) * 2 * 8) as u32) as u64)
                    .wrapping_div(size_of::<[u32; 2]>() as u64) as usize,
            );
            for k in 0..2 {
                let s0 = (((*p0.add(k))[1] as u64) << 32).wrapping_add((*p0.add(k))[0] as u64);
                let s1 = (((*p1.add(k))[1] as u64) << 32).wrapping_add((*p1.add(k))[0] as u64);
                xl = (*X.add(j))[k][0];
                xh = (*X.add(j))[k][1];
                let mut x = (xh as u64).wrapping_mul(xl as u64);
                x = x.wrapping_add(s0) as u64 as u64;
                x ^= s1;
                (*X.add(j))[k][0] = x as u32;
                (*X.add(j))[k][1] = (x >> 32) as u32;
                if i != 0usize && i != (6 - 1) {
                    (*S2.add(w))[0] = x as u32;
                    (*S2.add(w))[1] = (x >> 32) as u32;
                    w = w.wrapping_add(1);
                }
            }
        }
    }
    (*ctx).S0 = S2;
    (*ctx).S1 = S0;
    (*ctx).S2 = S1;
    (*ctx).w = w & (((1usize) << 8usize) * 2usize - 1usize);
}

unsafe fn blockmix_pwxform(B: *mut u32, ctx: *mut PwxformCtx, r: usize) {
    let mut X: [u32; 16] = [0; 16];
    let r1 = (128usize).wrapping_mul(r).wrapping_div(4 * 2 * 8);
    blkcpy(
        X.as_mut_ptr(),
        B.add(
            r1.wrapping_sub(1usize)
                .wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>())),
        ),
        (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
    );
    for i in 0..r1 {
        if r1 > 1 {
            blkxor(
                X.as_mut_ptr(),
                B.add(i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>()))),
                (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
            );
        }
        pwxform(X.as_mut_ptr(), ctx);
        blkcpy(
            B.add(i.wrapping_mul((4usize * 2 * 8).wrapping_div(size_of::<u32>()))),
            X.as_mut_ptr(),
            (4usize * 2 * 8).wrapping_div(size_of::<u32>()),
        );
    }
    let mut i = r1.wrapping_sub(1).wrapping_mul(4 * 2 * 8).wrapping_div(64);
    salsa20::salsa20_2(B.add(i.wrapping_mul(16)));
    i = i.wrapping_add(1);
    for i in i..(2usize).wrapping_mul(r) {
        blkxor(
            B.add(i.wrapping_mul(16usize)),
            B.add(i.wrapping_sub(1usize).wrapping_mul(16usize)),
            16_usize,
        );
        salsa20::salsa20_2(B.add(i.wrapping_mul(16)));
    }
}

unsafe fn smix(
    B: *mut u32,
    r: usize,
    N: u64,
    p: u32,
    t: u32,
    flags: Flags,
    V: *mut u32,
    NROM: u64,
    VROM: *const u32,
    XY: *mut u32,
    ctx: *mut PwxformCtx,
    passwd: *mut u8,
) {
    let s: usize = 32 * r;
    let mut Nchunk = N.wrapping_div(p as u64);
    let mut Nloop_all = Nchunk;
    if flags & 0x2_u32 != 0 {
        if t <= 1_u32 {
            if t != 0 {
                Nloop_all = Nloop_all.wrapping_mul(2_u64);
            }
            Nloop_all = Nloop_all.wrapping_add(2_u64).wrapping_div(3_u64);
        } else {
            Nloop_all = Nloop_all.wrapping_mul(t.wrapping_sub(1_u32) as u64);
        }
    } else if t != 0 {
        if t == 1_u32 {
            Nloop_all = Nloop_all.wrapping_add(Nloop_all.wrapping_add(1_u64).wrapping_div(2_u64));
        }
        Nloop_all = Nloop_all.wrapping_mul(t as u64);
    }
    let mut Nloop_rw = 0_u64;
    if flags & 0x1000000_u32 != 0 {
        Nloop_rw = Nloop_all;
    } else if flags & 0x2_u32 != 0 {
        Nloop_rw = Nloop_all.wrapping_div(p as u64);
    }
    Nchunk &= !1_u64;
    Nloop_all = Nloop_all.wrapping_add(1);
    Nloop_all &= !1_u64;
    Nloop_rw = Nloop_rw.wrapping_add(1);
    Nloop_rw &= !1_u64;
    let mut Vchunk = 0_u64;
    for i in 0..p {
        let Np: u64 = if i < p.wrapping_sub(1_u32) {
            Nchunk
        } else {
            N.wrapping_sub(Vchunk)
        };
        let Bp: *mut u32 = B.add((i as usize).wrapping_mul(s));
        let Vp: *mut u32 = V.add((Vchunk as usize).wrapping_mul(s));
        let mut ctx_i: *mut PwxformCtx = ptr::null_mut();
        if flags & 0x2_u32 != 0 {
            ctx_i = ctx.add(i as usize);
            smix1(
                Bp,
                1_usize,
                (3 * ((1) << 8) * 2 * 8 / 128) as u64,
                0 as Flags,
                (*ctx_i).S,
                0_u64,
                ptr::null(),
                XY,
                ptr::null_mut(),
            );
            (*ctx_i).S2 = (*ctx_i).S as *mut [u32; 2];
            (*ctx_i).S1 = ((*ctx_i).S2).add(((1) << 8) * 2);
            (*ctx_i).S0 = ((*ctx_i).S1).add(((1) << 8) * 2);
            (*ctx_i).w = 0_usize;
            if i == 0_u32 {
                HMAC_SHA256_Buf(
                    Bp.add(s.wrapping_sub(16)).cast::<u8>(),
                    64_usize,
                    passwd,
                    32_usize,
                    passwd,
                );
            }
        }
        smix1(Bp, r, Np, flags, Vp, NROM, VROM, XY, ctx_i);
        smix2(
            Bp,
            r,
            prev_power_of_two(Np),
            Nloop_rw,
            flags,
            Vp,
            NROM,
            VROM,
            XY,
            ctx_i,
        );
        Vchunk = Vchunk.wrapping_add(Nchunk);
    }
    for i in 0..p {
        let Bp_0: *mut u32 = B.add((i as usize).wrapping_mul(s));
        smix2(
            Bp_0,
            r,
            N,
            Nloop_all.wrapping_sub(Nloop_rw),
            flags & !(0x2),
            V,
            NROM,
            VROM,
            XY,
            if flags & 0x2_u32 != 0 {
                ctx.add(i as usize)
            } else {
                ptr::null_mut()
            },
        );
    }
}

unsafe fn smix1(
    B: *mut u32,
    r: usize,
    N: u64,
    flags: Flags,
    V: *mut u32,
    NROM: u64,
    VROM: *const u32,
    XY: *mut u32,
    ctx: *mut PwxformCtx,
) {
    let s: usize = (32usize).wrapping_mul(r);
    let X: *mut u32 = XY;
    let Y: *mut u32 = XY.add(s);
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            *X.add(k.wrapping_mul(16usize).wrapping_add(i)) = le32dec(
                B.add(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize)),
                ),
            );
        }
    }
    for i in 0..N {
        blkcpy(V.add(usize::try_from(i).unwrap().wrapping_mul(s)), X, s);
        if !VROM.is_null() && i == 0_u64 {
            blkxor(
                X,
                VROM.add(
                    usize::try_from(NROM)
                        .unwrap()
                        .wrapping_sub(1)
                        .wrapping_mul(s),
                ),
                s,
            );
        } else if !VROM.is_null() && i & 1_u64 != 0 {
            let j = integerify(X, r) & NROM.wrapping_sub(1);
            blkxor(X, VROM.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);
        } else if flags & 0x2_u32 != 0 && i > 1_u64 {
            let j = wrap(integerify(X, r), i);
            blkxor(X, V.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);
        }
        if !ctx.is_null() {
            blockmix_pwxform(X, ctx, r);
        } else {
            salsa20::blockmix_salsa8(X, Y, r);
        }
    }
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            le32enc(
                B.add(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize)),
                ),
                *X.add(k.wrapping_mul(16usize).wrapping_add(i)),
            );
        }
    }
}

unsafe fn smix2(
    B: *mut u32,
    r: usize,
    N: u64,
    Nloop: u64,
    flags: Flags,
    V: *mut u32,
    NROM: u64,
    VROM: *const u32,
    XY: *mut u32,
    ctx: *mut PwxformCtx,
) {
    let s: usize = (32usize).wrapping_mul(r);
    let X: *mut u32 = XY;
    let Y: *mut u32 = XY.add(s);
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            *X.add(k.wrapping_mul(16usize).wrapping_add(i)) = le32dec(
                B.add(
                    k.wrapping_mul(16usize)
                        .wrapping_add(i.wrapping_mul(5usize).wrapping_rem(16usize)),
                ),
            );
        }
    }
    for i in 0..Nloop {
        if !VROM.is_null() && i & 1 != 0 {
            let j = integerify(X, r) & NROM.wrapping_sub(1);
            blkxor(X, VROM.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);
        } else {
            let j = integerify(X, r) & N.wrapping_sub(1);
            blkxor(X, V.add(usize::try_from(j).unwrap().wrapping_mul(s)), s);
            if flags & 0x2_u32 != 0 {
                blkcpy(V.add(usize::try_from(j).unwrap().wrapping_mul(s)), X, s);
            }
        }
        if !ctx.is_null() {
            blockmix_pwxform(X, ctx, r);
        } else {
            salsa20::blockmix_salsa8(X, Y, r);
        }
    }
    for k in 0..(2usize).wrapping_mul(r) {
        for i in 0..16usize {
            le32enc(
                B.add(
                    k.wrapping_mul(16)
                        .wrapping_add(i.wrapping_mul(5).wrapping_rem(16)),
                ),
                *X.add(k.wrapping_mul(16).wrapping_add(i)),
            );
        }
    }
}
