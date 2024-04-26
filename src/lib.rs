#![allow(unused)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod params;
pub mod poly;

use params::NTRUParams;
use poly::{int_log2, Polynomial};

#[derive(Debug)]
pub struct KeyPair<const N: usize, const P: i16, const Q: i16> {
    pub pubkey: PublicKey<N, P, Q>,
    pub privkey: PrivateKey<N, P, Q>,
}

impl<const N: usize, const P: i16, const Q: i16> KeyPair<N, P, Q> {
    pub fn encrypt(&self, data: &[u8], params: &NTRUParams<N, P, Q>) -> Vec<u8>
    where
        [(); { N + 1 }]:,
    {
        self.pubkey.encrypt(data, params)
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.privkey.decrypt(data)
    }

    pub fn split(self) -> (PublicKey<N, P, Q>, PrivateKey<N, P, Q>) {
        (self.pubkey, self.privkey)
    }

    pub fn as_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (self.pubkey.as_bytes(), self.privkey.as_bytes())
    }
}

/// Public key used to encrypt data so that it can only be decrypted by the
/// matching private key.
#[derive(Debug)]
pub struct PublicKey<const N: usize, const P: i16, const Q: i16> {
    pub key: Polynomial<N>,
}

impl<const N: usize, const P: i16, const Q: i16> PublicKey<N, P, Q> {
    pub fn encrypt(&self, data: &[u8], params: &NTRUParams<N, P, Q>) -> Vec<u8>
    where
        [(); { N + 1 }]:,
    {
        let polys = Polynomial::<N>::encode::<P>(data);
        let encrypted = polys
            .into_iter()
            .map(|m| {
                let r = Polynomial::<N>::rand_ternary_t(params.d_phi, params.d_phi)
                    .denormalize(P as u32);
                self.key.mul(r, Q as u32).add(m, Q as u32)
            })
            .collect::<Vec<_>>();

        Polynomial::<N>::decode::<Q>(encrypted.as_slice())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        Polynomial::decode::<Q>(vec![self.key].as_slice())
    }
}

/// Private key used to decrypt data encrypted by the matching Public key.
#[derive(Debug)]
pub struct PrivateKey<const N: usize, const P: i16, const Q: i16> {
    pub key_f: Polynomial<N>,
    pub key_fp: Polynomial<N>,
}

impl<const N: usize, const P: i16, const Q: i16> PrivateKey<N, P, Q> {
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let polys = Polynomial::<N>::encode::<Q>(data);

        let decrypted = polys
            .into_iter()
            .map(|e| {
                let a = self.key_f.mul(e, Q as u32);
                let b = a.denormalize(Q as u32).normalize(P as u32);
                let c = self.key_fp.mul(b, P as u32);
                c
            })
            .collect::<Vec<_>>();

        Polynomial::<N>::decode::<P>(decrypted.as_slice())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        Polynomial::decode::<Q>(vec![self.key_f, self.key_fp].as_slice())
    }
}

pub fn keygen<const N: usize, const P: i16, const Q: i16>(
    params: &NTRUParams<N, P, Q>,
) -> KeyPair<N, P, Q>
where
    [(); { N + 1 }]:,
    [(); { N - 1 }]:,
{
    let one = Polynomial::new_one();
    let g = Polynomial::<N>::rand_ternary_t(params.d_g, params.d_g);

    let mut f;
    let mut f_p;
    let mut f_q;

    loop {
        f = Polynomial::<N>::rand_ternary_t(params.d_f, params.d_f - 1);
        if let Some(f_invq) = f
            .normalize(Q as u32)
            .inverse_power_prime(2, int_log2(Q) as u8)
        {
            f_q = f_invq.denormalize(Q as u32);
            if f.normalize(Q as u32).mul(f_q, Q as u32) != one {
                continue;
            }
            if let Some(f_invp) = f.normalize(P as u32).inverse_gcd(P as u32) {
                f_p = f_invp;
                if f.normalize(P as u32).mul(f_p, P as u32) != one {
                    continue;
                }
                break;
            }
        }
    }

    let h = (f_q.normalize(Q as u32).mul_scalar(P, Q as u32))
        .mul(g.normalize(Q as u32), Q as u32)
        .denormalize(Q as u32);

    return KeyPair {
        pubkey: PublicKey { key: h },
        privkey: PrivateKey {
            key_f: f,
            key_fp: f_p,
        },
    };
}
