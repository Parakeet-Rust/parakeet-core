// Adapted from cipher::cbc
// src: https://github.com/RustCrypto/block-modes/blob/master/cbc/src/decrypt.rs

pub(crate) mod detail {
    use cipher::{
        crypto_common::{InnerInit, InnerUser},
        generic_array::ArrayLength,
        inout::InOut,
        AlgorithmName, Block, BlockBackend, BlockCipher, BlockClosure, BlockDecryptMut,
        BlockSizeUser, ParBlocks, ParBlocksSizeUser,
    };
    use core::fmt;

    #[cfg(feature = "zeroize")]
    use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

    /// ECB mode decryptor.
    #[derive(Clone)]
    pub struct Decryptor<C>
    where
        C: BlockDecryptMut + BlockCipher,
    {
        cipher: C,
    }

    impl<C> BlockSizeUser for Decryptor<C>
    where
        C: BlockDecryptMut + BlockCipher,
    {
        type BlockSize = C::BlockSize;
    }

    impl<C> BlockDecryptMut for Decryptor<C>
    where
        C: BlockDecryptMut + BlockCipher,
    {
        fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
            let Self { cipher } = self;
            cipher.decrypt_with_backend_mut(Closure { f })
        }
    }

    impl<C> InnerUser for Decryptor<C>
    where
        C: BlockDecryptMut + BlockCipher,
    {
        type Inner = C;
    }

    impl<C> InnerInit for Decryptor<C>
    where
        C: BlockDecryptMut + BlockCipher,
    {
        fn inner_init(inner: Self::Inner) -> Self {
            Self { cipher: inner }
        }
    }

    impl<C> AlgorithmName for Decryptor<C>
    where
        C: BlockDecryptMut + BlockCipher + AlgorithmName,
    {
        fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ecb::Decryptor<")?;
            <C as AlgorithmName>::write_alg_name(f)?;
            f.write_str(">")
        }
    }

    impl<C> fmt::Debug for Decryptor<C>
    where
        C: BlockDecryptMut + BlockCipher + AlgorithmName,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ecb::Decryptor<")?;
            <C as AlgorithmName>::write_alg_name(f)?;
            f.write_str("> { ... }")
        }
    }

    #[cfg(feature = "zeroize")]
    #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
    impl<C: BlockDecryptMut + BlockCipher> Drop for Decryptor<C> {
        fn drop(&mut self) {}
    }

    #[cfg(feature = "zeroize")]
    #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
    impl<C: BlockDecryptMut + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for Decryptor<C> {}

    struct Closure<BS, BC>
    where
        BS: ArrayLength<u8>,
        BC: BlockClosure<BlockSize = BS>,
    {
        f: BC,
    }

    impl<BS, BC> BlockSizeUser for Closure<BS, BC>
    where
        BS: ArrayLength<u8>,
        BC: BlockClosure<BlockSize = BS>,
    {
        type BlockSize = BS;
    }

    impl<BS, BC> BlockClosure for Closure<BS, BC>
    where
        BS: ArrayLength<u8>,
        BC: BlockClosure<BlockSize = BS>,
    {
        #[inline(always)]
        fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
            let Self { f } = self;
            f.call(&mut Backend { backend });
        }
    }

    struct Backend<'a, BS, BK>
    where
        BS: ArrayLength<u8>,
        BK: BlockBackend<BlockSize = BS>,
    {
        backend: &'a mut BK,
    }

    impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
    where
        BS: ArrayLength<u8>,
        BK: BlockBackend<BlockSize = BS>,
    {
        type BlockSize = BS;
    }

    impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
    where
        BS: ArrayLength<u8>,
        BK: BlockBackend<BlockSize = BS>,
    {
        type ParBlocksSize = BK::ParBlocksSize;
    }

    impl<'a, BS, BK> BlockBackend for Backend<'a, BS, BK>
    where
        BS: ArrayLength<u8>,
        BK: BlockBackend<BlockSize = BS>,
    {
        #[inline(always)]
        fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
            let in_block = block.clone_in();
            let mut t = block.clone_in();
            self.backend.proc_block((&mut t).into());
            *block.get_out() = t;
        }

        #[inline(always)]
        fn proc_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
            let in_blocks = blocks.clone_in();
            let mut t = blocks.clone_in();

            self.backend.proc_par_blocks((&mut t).into());
            let n = t.len();
            *blocks.get_out() = t;
        }
    }
}

use aes;
pub(crate) type Aes128EcbDec = detail::Decryptor<aes::Aes128>;
