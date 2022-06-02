use super::array_ext::ArrayExtension;

pub trait RC4Derive {
    fn next(&mut self) -> u8;
}

pub struct RC4State {
    s: [u8; 256],
}

impl RC4State {
    #[inline(always)]
    fn new<T: AsRef<[u8]>>(key: T) -> Self {
        let key = key.as_ref();
        let mut data = Self { s: [0u8; 256] };

        for (i, v) in data.s.iter_mut().enumerate() {
            *v = i as u8;
        }

        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(data.s[i]).wrapping_add(key.get_mod_n(i));
            data.s.swap(i, usize::from(j));
        }

        data
    }

    #[inline(always)]
    pub fn swap(&mut self, a: u8, b: u8) {
        self.s.swap(a.into(), b.into());
    }

    #[inline(always)]
    pub fn get(&self, i: u8) -> u8 {
        self.s[i as usize]
    }

    #[inline(always)]
    pub fn get_and_add(&self, i: u8, j: u8) -> u8 {
        let i = self.get(i);
        let j = self.get(j);
        self.get(i.wrapping_add(j))
    }
}

pub struct RC4Standard {
    s: RC4State,
    i: u8,
    j: u8,
}

impl RC4Standard {
    #[inline(always)]
    pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
        Self {
            s: RC4State::new(key),
            i: 0,
            j: 0,
        }
    }
}

impl RC4Derive for RC4Standard {
    #[inline(always)]
    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s.get(self.i));
        self.s.swap(self.i, self.j);
        self.s.get_and_add(self.i, self.j)
    }
}
