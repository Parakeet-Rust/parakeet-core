use crate::{impl_rc4_init, utils::array_ext::ArrayExtension};

use super::rc4::RC4Derive;

pub struct RC4TencentQmcV2 {
    s: Vec<u8>,
    s_original: Vec<u8>,
    i: usize,
    j: usize,
}

impl RC4TencentQmcV2 {
    impl_rc4_init! {}

    #[inline(always)]
    pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
        let n = key.as_ref().len();
        let mut result = Self {
            s: vec![0u8; n],
            s_original: vec![],
            i: 0,
            j: 0,
        };
        result.init(key, n);
        result.s_original = result.s.clone();
        result
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        self.s = self.s_original.clone();
        self.i = 0;
        self.j = 0;
    }

    #[inline(always)]
    pub fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.next();
        }
    }

    #[inline(always)]
    fn get_and_add_usize(&self, i: usize, j: usize) -> u8 {
        let s = self.get_state();
        let i = s.get_mod_n(i) as usize;
        let j = s.get_mod_n(j) as usize;
        s.get_mod_n(i.wrapping_add(j))
    }
}

impl RC4Derive for RC4TencentQmcV2 {
    #[inline(always)]
    fn get_state(&self) -> &[u8] {
        self.s.as_slice()
    }

    #[inline(always)]
    fn next(&mut self) -> u8 {
        let n = self.s.len();
        let i = self.i.wrapping_add(1) % n;
        let j = self.j.wrapping_add(self.s.at(i).into()) % n;

        (self.i, self.j) = (i, j);
        self.s.swap_unsigned_index(i, j);
        self.get_and_add_usize(i, j)
    }
}
