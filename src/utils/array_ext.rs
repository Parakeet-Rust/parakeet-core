use std::mem::size_of;

use num_traits::PrimInt;

pub trait VecExtension {
    fn append_of_size(&mut self, len: usize) -> &mut [u8];
    fn append_data<T: AsRef<[u8]>>(&mut self, data: T) -> &mut [u8];
}

impl VecExtension for Vec<u8> {
    fn append_of_size(&mut self, len: usize) -> &mut [u8] {
        let i = self.len();
        let mut data = vec![0u8; len];
        self.append(&mut data);
        &mut self[i..]
    }
    fn append_data<T: AsRef<[u8]>>(&mut self, data: T) -> &mut [u8] {
        let i = self.len();
        self.extend_from_slice(data.as_ref());
        &mut self[i..]
    }
}

pub trait IntHelper {
    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn from_be_bytes(bytes: &[u8]) -> Self;

    fn read_le(bytes: &[u8], offset: usize) -> Self;
    fn read_be(bytes: &[u8], offset: usize) -> Self;

    // faster mod for our use case.
    // we usually pass in a large offset to look-up values from
    //   a small table, which is faster than doing div/mul for
    //   modular calculation.
    // src: https://stackoverflow.com/a/33333924
    fn fast_mod(&self, rhs: Self) -> Self;
}

macro_rules! impl_int_helper (( $($int:ident),* ) => {
    $(
        impl IntHelper for $int {
            #[inline(always)]
            fn from_le_bytes(bytes: &[u8]) -> Self {
                Self::from_le_bytes(bytes[..size_of::<Self>()].try_into().unwrap())
            }
            #[inline(always)]
            fn from_be_bytes(bytes: &[u8]) -> Self {
                Self::from_be_bytes(bytes[..size_of::<Self>()].try_into().unwrap())
            }

            #[inline(always)]
            fn read_le(bytes: &[u8], offset: usize) -> Self {
                Self::from_le_bytes(bytes[offset..offset + size_of::<Self>()].try_into().unwrap())
            }

            #[inline(always)]
            fn read_be(bytes: &[u8], offset: usize) -> Self {
                Self::from_be_bytes(bytes[offset..offset + size_of::<Self>()].try_into().unwrap())
            }

            #[inline(always)]
            fn fast_mod(&self, rhs: Self) -> Self {
                let lhs = *self;
                if lhs < rhs {
                    lhs
                } else {
                    lhs % rhs
                }
            }
        }
    )*
});

impl_int_helper!(u8, u16, u32, u64, u128, usize);
impl_int_helper!(i8, i16, i32, i64, i128, isize);

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

    fn swap_unsigned_index<I: USizeable, J: USizeable>(&mut self, a: I, b: J);
    fn at<I: USizeable>(&self, a: I) -> T;
}

impl<T: PrimInt> ArrayExtension<T> for [T] {
    #[inline(always)]
    fn get_value_unchecked<I: USizeable>(&self, i: I) -> T {
        unsafe { *self.get_unchecked(i.to_usize()) }
    }
    #[inline(always)]
    fn get_mod_n<I: USizeable>(&self, i: I) -> T {
        let i = i.to_usize();

        let n = self.len();
        self.get_value_unchecked(i.fast_mod(n))
    }
    #[inline(always)]
    fn swap_unsigned_index<I: USizeable, J: USizeable>(&mut self, a: I, b: J) {
        self.swap(a.to_usize(), b.to_usize());
    }
    #[inline(always)]
    fn at<I: USizeable>(&self, a: I) -> T {
        self[a.to_usize()]
    }
}

pub trait ByteSliceExt {
    fn read_le<R: PrimInt + IntHelper>(&self, offset: usize) -> R;
    fn read_be<R: PrimInt + IntHelper>(&self, offset: usize) -> R;

    fn xor_key_with_key_offset<T: AsRef<[u8]>>(&mut self, key: T, offset: usize);
    #[inline(always)]
    fn xor_key<T: AsRef<[u8]>>(&mut self, key: T) {
        self.xor_key_with_key_offset(key, 0)
    }

    unsafe fn set_unchecked(&mut self, i: usize, value: u8);
}

impl ByteSliceExt for [u8] {
    #[inline(always)]
    fn read_le<R: PrimInt + IntHelper>(&self, offset: usize) -> R {
        R::read_le(self, offset)
    }
    #[inline(always)]
    fn read_be<R: PrimInt + IntHelper>(&self, offset: usize) -> R {
        R::read_be(self, offset)
    }

    #[inline(always)]
    fn xor_key_with_key_offset<T: AsRef<[u8]>>(&mut self, key: T, offset: usize) {
        let key = key.as_ref();
        let n = key.len();
        let mut offset = offset % n;

        for v in self.iter_mut() {
            *v ^= key.get_value_unchecked(offset);

            offset += 1;
            if offset == n {
                offset = 0;
            }
        }
    }

    #[inline(always)]
    unsafe fn set_unchecked(&mut self, i: usize, value: u8) {
        *self.get_unchecked_mut(i) = value;
    }
}
