use std::mem::size_of;

use num_traits::PrimInt;

pub trait EndianOp {
    type Array;
    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn from_be_bytes(bytes: &[u8]) -> Self;
}

macro_rules! impl_endian_op (( $($int:ident),* ) => {
    $(
        impl EndianOp for $int {
            type Array = [u8; std::mem::size_of::<Self>()];
            fn from_le_bytes(bytes: &[u8]) -> Self { Self::from_le_bytes(bytes[..size_of::<Self>()].try_into().expect("invalid bytes size")) }
            fn from_be_bytes(bytes: &[u8]) -> Self { Self::from_be_bytes(bytes[..size_of::<Self>()].try_into().expect("invalid bytes size")) }
        }
    )*
});

impl_endian_op!(u8, u16, u32, u64, u128, usize);
impl_endian_op!(i8, i16, i32, i64, i128, isize);

pub trait ArrayExtension<T: PrimInt> {
    fn get_mod_n(&self, i: usize) -> T;
}

impl<T: PrimInt, const SIZE: usize> ArrayExtension<T> for [T; SIZE] {
    #[inline(always)]
    fn get_mod_n(&self, i: usize) -> T {
        self[i % self.len()]
    }
}

pub trait ByteSliceExt {
    fn read_le<R: PrimInt + EndianOp>(&self, offset: usize) -> R;
}

macro_rules! impl_byte_slice_ext (( $($type:ty),* ) => {
    $(
        impl ByteSliceExt for $type {
            #[inline(always)]
            fn read_le<R: PrimInt + EndianOp>(&self, offset: usize) -> R {
                R::from_le_bytes(&self[offset..])
            }
        }
    )*
});

impl_byte_slice_ext!([u8]);
impl_byte_slice_ext!(Vec<u8>);
