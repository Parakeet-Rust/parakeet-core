use crate::{impl_rc4_state_getter, utils::array_ext::ArrayExtension};

use super::rc4::{RC4Derive, RC4State};

pub struct RC4Standard {
    state: RC4State,
    i: u8,
    j: u8,
}

impl RC4Standard {
    #[inline(always)]
    #[allow(dead_code)]
    pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
        Self {
            state: RC4State::new(key),
            i: 0,
            j: 0,
        }
    }
}

impl RC4Derive for RC4Standard {
    impl_rc4_state_getter! {}

    #[inline(always)]
    fn next(&mut self) -> u8 {
        let i = self.i.wrapping_add(1);
        let j = self.j.wrapping_add(self.state.s.at(i));

        (self.i, self.j) = (i, j);
        self.state.s.swap_unsigned_index(i, j);
        self.get_and_add(i, j)
    }
}
