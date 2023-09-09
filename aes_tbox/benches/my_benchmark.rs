#![allow(unused)]
use aes_tbox::aes_encrypt;
use aes_tbox::{aes_enc::State, key_exp::Key};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn my_aes_encryption(c: &mut Criterion) {
    let key = Key::from([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ]);

    let mut cleartext = State::from([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);

    c.bench_function("my aes encryption", |b| {
        b.iter(|| aes_encrypt(black_box(&mut cleartext), black_box(&key)))
    });
}

criterion_group!(benches, my_aes_encryption);
criterion_main!(benches);
