pub mod joox;
pub mod kugou;
pub mod kuwo;
pub mod ncm;
pub mod ximalaya;

mod qmc;
mod qmc_v1;
mod qmc_v2;

// Kugou
pub use kugou::new_kgm;
pub use kugou::new_vpr;

// Kuwo
pub use kuwo::new_kwm;

// Netease
pub use ncm::new_ncm;

// Tencent QQMusic (QMC)
pub use qmc::new_qmc_v2;
pub use qmc_v1::new_qmc_v1_static as new_qmc_v1;

// Ximalaya
pub use ximalaya::new_x2m;
pub use ximalaya::new_x3m;
