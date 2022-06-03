use crate::{impl_rc4_state_getter, utils::array_ext::ArrayExtension};

use super::rc4::{RC4Derive, RC4State};

pub struct RC4Netease {
    state: RC4State,
    i: u8,
}

impl RC4Netease {
    #[inline(always)]
    pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
        Self {
            state: RC4State::new(key),
            i: 0,
        }
    }
}

impl RC4Derive for RC4Netease {
    impl_rc4_state_getter! {}

    #[inline(always)]
    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);

        let i = self.i;
        let j = self.get_state().at(i).wrapping_add(i);

        self.get_and_add(i, j)
    }
}
