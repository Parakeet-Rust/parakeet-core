pub mod kugou;
pub mod kuwo;
pub mod ncm;
pub mod ximalaya;

mod qmc;
mod qmc_v1;
mod qmc_v2;

pub use qmc::new_qmc_v2;
pub use qmc_v1::new_qmc_v1_static as new_qmc_v1;
