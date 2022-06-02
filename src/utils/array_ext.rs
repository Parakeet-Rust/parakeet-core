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
            #[inline(always)]
            fn from_le_bytes(bytes: &[u8]) -> Self {
                Self::from_le_bytes(bytes[..size_of::<Self>()].try_into().unwrap())
            }
            #[inline(always)]
            fn from_be_bytes(bytes: &[u8]) -> Self {
                Self::from_be_bytes(bytes[..size_of::<Self>()].try_into().unwrap())
            }
        }
    )*
});

impl_endian_op!(u8, u16, u32, u64, u128, usize);
impl_endian_op!(i8, i16, i32, i64, i128, isize);

pub trait USizeable {
    fn to_usize(&self) -> usize;
}

macro_rules! impl_unsigned_sizeable_from (( $($int:ident),* ) => {
    $(
        impl USizeable for $int {
            #[inline(always)]
            fn to_usize(&self) -> usize {
                *self as usize
            }
        }
    )*
});
impl_unsigned_sizeable_from!(u8, u16, u32, usize);

pub trait ArrayExtension<T: PrimInt> {
    fn get_mod_n<I: USizeable>(&self, i: I) -> T;
    fn get_value_unchecked<I: USizeable>(&self, i: I) -> T;
}

impl<T: PrimInt> ArrayExtension<T> for [T] {
    #[inline(always)]
    fn get_value_unchecked<I: USizeable>(&self, i: I) -> T {
        unsafe { *self.get_unchecked(i.to_usize()) }
    }
    #[inline(always)]
    fn get_mod_n<I: USizeable>(&self, i: I) -> T {
        let i = i.to_usize();

        // faster mod for our use case.
        // we usually pass in a large offset to look-up values from
        //   a small table, which is faster than doing div/mul for
        //   modular calculation.
        // src: https://stackoverflow.com/a/33333924
        let n = self.len();
        let i = if i < n { i } else { i % n };
        self.get_value_unchecked(i)
    }
}

pub trait ByteSliceExt {
    fn read_le<R: PrimInt + EndianOp>(&self, offset: usize) -> R;

    fn xor_key_with_key_offset<T: AsRef<[u8]>>(&mut self, key: T, offset: usize);
    #[inline(always)]
    fn xor_key<T: AsRef<[u8]>>(&mut self, key: T) {
        self.xor_key_with_key_offset(key, 0)
    }

    unsafe fn set_unchecked(&mut self, i: usize, value: u8);
}

impl ByteSliceExt for [u8] {
    #[inline(always)]
    fn read_le<R: PrimInt + EndianOp>(&self, offset: usize) -> R {
        R::from_le_bytes(&self[offset..])
    }

    #[inline(always)]
    fn xor_key_with_key_offset<T: AsRef<[u8]>>(&mut self, key: T, offset: usize) {
        let key = key.as_ref();
        let n = key.len();
        let offset = offset % n;

        for (i, v) in self.iter_mut().enumerate() {
            *v ^= key.get_mod_n(offset + i);
        }
    }

    #[inline(always)]
    unsafe fn set_unchecked(&mut self, i: usize, value: u8) {
        *self.get_unchecked_mut(i) = value;
    }
}
