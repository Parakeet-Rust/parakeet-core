use super::super::array_ext::ArrayExtension;

pub trait RC4Derive {
    fn get_state(&self) -> &[u8];

    #[inline(always)]
    fn get_and_add(&self, i: u8, j: u8) -> u8 {
        let s = self.get_state();
        let i = s.at(i);
        let j = s.at(j);
        s.at(i.wrapping_add(j))
    }

    fn next(&mut self) -> u8;
}

pub struct RC4State {
    pub(crate) s: [u8; 256],
}

#[macro_export]
macro_rules! impl_rc4_state_getter {
    () => {
        #[inline(always)]
        fn get_state(&self) -> &[u8] {
            &self.state.s
        }
    };
}

#[macro_export]
macro_rules! impl_rc4_init {
    () => {
        #[inline(always)]
        fn init<T: AsRef<[u8]>>(&mut self, key: T, n: usize) {
            let key = key.as_ref();

            for (i, v) in self.s.iter_mut().enumerate() {
                *v = i as u8;
            }

            let mut j = 0usize;
            for i in 0..n {
                j = j
                    .wrapping_add(self.s[i].into())
                    .wrapping_add(key.get_mod_n(i).into());
                j %= n;
                self.s.swap(i, j);
            }
        }
    };
}

impl RC4State {
    impl_rc4_init!();

    #[inline(always)]
    pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
        let mut result = Self { s: [0u8; 256] };
        result.init(key, 256);
        result
    }
}
