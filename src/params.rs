#[derive(Copy, Clone)]
pub struct NTRUParams<const N: usize, const P: i16, const Q: i16> {
    pub d_f: usize,
    pub d_g: usize,
    pub d_phi: usize,
}

pub const NTRU_EXAMPLE: NTRUParams<11, 3, 32> = NTRUParams {
    d_f: 4,
    d_g: 3,
    d_phi: 1,
};

pub const NTRU_PAPER_MODERATE: NTRUParams<107, 3, 64> = NTRUParams {
    d_f: 15,
    d_g: 12,
    d_phi: 5,
};

pub const NTRU_PAPER_HIGH: NTRUParams<167, 3, 128> = NTRUParams {
    d_f: 61,
    d_g: 20,
    d_phi: 18,
};

pub const NTRU_PAPER_HIGHEST: NTRUParams<503, 3, 256> = NTRUParams {
    d_f: 216,
    d_g: 72,
    d_phi: 55,
};
