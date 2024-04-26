use std::{
    fmt::{Debug, Display},
    ops::{Add, AddAssign, Mul, MulAssign, Rem, RemAssign, SubAssign},
    process::Output,
};

use rand::Rng;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Polynomial<const N: usize>([i16; N]);

impl<const N: usize> Polynomial<N> {
    /// Creates a new vector from a given slice.
    pub fn new(p: [i16; N]) -> Self {
        Polynomial(p)
    }

    pub fn new_zero() -> Self {
        Polynomial::new([0; N])
    }

    pub fn new_one() -> Self {
        let mut out = Polynomial::new([0; N]);
        out.set(0, 1);
        out
    }

    pub fn copy(&mut self, rhs: Self) {
        for i in 0..N {
            self.0[i] = rhs.0[i];
        }
    }

    /// Creates a new vector from a given constant.
    pub fn new_constant(c: i16) -> Self {
        let mut p = [0; N];
        p[0] = c;
        Polynomial(p)
    }

    /// Creates a new polynomial with coefficients reduced modulo 3
    /// uses rand::thread_rng(), which is secure.
    pub fn rand_ternary() -> Self {
        // rand::thread_rng() is a cryptographically secure PRNG, seeded by
        // the operating system. See
        // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
        let mut rng = rand::thread_rng();
        let mut p = Polynomial::new([0; N]);

        for i in 0..N {
            p.0[i] = (rng.gen::<u64>() % 3) as i16;
        }

        // returns p with {-1, 0, 1} rather than {0, 1, 2}.
        p.denormalize(3)
    }

    pub fn rand_ternary_t(pos: usize, neg: usize) -> Self {
        let mut rng = rand::thread_rng();

        let mut p = Polynomial::new([0; N]);

        for i in 0..pos {
            p.set(i, 1);
        }
        for i in pos..(pos + neg) {
            p.set(i, -1);
        }

        // shuffle
        for i in (0..N).rev() {
            let j = rng.gen::<usize>() % (i + 1);
            p.swap(i, j);
        }

        p
    }

    /// Sets the value of a power to a given coefficient.
    pub fn set(&mut self, power: usize, coeff: i16) {
        self.0[power] = coeff;
    }

    pub fn swap(&mut self, i: usize, j: usize) {
        (self.0[i], self.0[j]) = (self.0[j], self.0[i])
    }

    /// Adds additional zero terms, changing the modulus and maximum degree of
    /// the vector.
    pub fn extend<const M: usize>(self) -> Polynomial<M> {
        if M >= N {
            let mut new = [0; M];
            for i in 0..N {
                new[i] = self.0[i];
            }
            Polynomial::new(new)
        } else {
            let mut new = [0; M];
            for i in 0..M {
                new[i] = self.0[i];
            }
            Polynomial::new(new)
        }
    }

    /// Checks whether the vector is equal to the zero vector.
    pub fn zero(&self) -> bool {
        for i in 0..N {
            if self.0[i] != 0 {
                return false;
            }
        }
        return true;
    }

    /// Moves the contents of the vector down 1, filling in with 0X^(N-1)
    pub fn shift_div_x(&mut self) {
        for i in 1..N {
            self.0[i - 1] = self.0[i];
        }
        self.0[N - 1] = 0;
    }

    pub fn div_x(&mut self, modulus: u32) {
        // println!("({self})/x");
        let a0 = self.0[0] as i64;
        for i in 1..N {
            self.0[i - 1] = self.0[i];
        }
        self.0[N - 1] = a0 as i16;
        self.0[0] = ((self.0[0] as i64 - a0 + modulus as i64) % modulus as i64) as i16;
    }

    /// Moves the contents of the vector up 1, filling in with constant 0
    pub fn shift_mul_x(&mut self) {
        for i in (1..N).rev() {
            self.0[i] = self.0[i - 1];
        }
        self.0[0] = 0;
    }

    /// Gets the maximum degree of the vector
    pub fn degree(&self) -> usize {
        for i in (0..N).rev() {
            if self.0[i] != 0 {
                return i;
            }
        }
        // is zero
        return 0;
    }

    pub fn normalize(mut self, modulus: u32) -> Self {
        for i in 0..N {
            self.0[i] =
                (((self.0[i] as i32 % modulus as i32) + modulus as i32) % modulus as i32) as i16
        }
        self
    }

    pub fn denormalize(mut self, modulus: u32) -> Self {
        for i in 0..N {
            if self.0[i] > (modulus / 2) as i16 {
                self.0[i] -= modulus as i16;
            }
        }
        self
    }

    pub fn add(mut self, rhs: Self, modulus: u32) -> Self {
        for i in 0..N {
            self.0[i] = ((self.0[i] + rhs.0[i]) as i32 % modulus as i32) as i16;
        }
        self
    }

    pub fn sub(mut self, rhs: Self, modulus: u32) -> Self {
        for i in 0..N {
            self.0[i] = (((self.0[i] - rhs.0[i]) as i32 + modulus as i32) as u32 % modulus) as i16;
        }
        self
    }

    pub fn mul(self, rhs: Polynomial<N>, modulus: u32) -> Self {
        let mut acc: [i64; N] = [0; N];

        for i in 0..N {
            for j in 0..N {
                acc[(i + j) % N] += self.0[i] as i64 * rhs.0[j] as i64;
            }
        }

        let mut out = [0; N];
        for i in 0..N {
            out[i] = ((acc[i] % modulus as i64) as i16 + modulus as i16) % modulus as i16
        }

        Polynomial::new(out)
    }

    pub fn mul_scalar(mut self, rhs: i16, modulus: u32) -> Self {
        for i in 0..N {
            self.0[i] *= rhs;
        }
        self.normalize(modulus)
    }

    /// Performs polynomial long division, returning the quotient and remainder
    pub fn div(mut self, mut rhs: Polynomial<N>, modulus: u32) -> Option<(Self, Self)> {
        let mut quo = Self::new_zero();
        let rd = rhs.degree();
        let d = self.degree();
        if rd > d {
            return Some((quo, self));
        }
        let inv = int_inverse(rhs.0[rd], modulus);
        let mut c = d - rd;

        // shift rhs to have same degree as self
        for _ in 0..c {
            rhs.shift_mul_x();
        }

        // subtract rhs and shift c times. rhs should end as the same value.
        // and quo will be
        for ind in (0..=c).rev() {
            let coeff = self.0[ind + rd]; // highest coefficient.
            let k = ((coeff as i64 * inv as i64) % modulus as i64) as i16;

            self.sub_multiple(rhs, k, modulus);

            /*
            if self.0[ind + rd] != 0 {
                return None;
            }
            */

            rhs.shift_div_x();

            quo.set(ind, k);
        }

        Some((quo, self))
    }

    /// Subtracts u copies of b from self, modulo MOD
    pub fn sub_multiple(&mut self, mut b: Polynomial<N>, u: i16, modulus: u32) {
        b = b.mul_scalar(u, modulus);

        for i in 0..N {
            self.0[i] -= b.0[i];
            self.0[i] = (self.0[i] + modulus as i16) % modulus as i16;
        }
    }

    pub fn reduce<const M: usize>(self, modulus: u32) -> Polynomial<M> {
        let mut b = Polynomial::new_zero();
        for i in 0..M {
            b.set(i, self.0[i]);
        }
        b.set(0, (b.0[0] + self.0[N - 1]) % modulus as i16);
        // b.set(0, (b.0[1] + self.0[N - 1]) % modulus as i16);
        b
    }

    pub fn inverse_gcd(self, modulus: u32) -> Option<Self>
    where
        [(); { N + 1 }]:,
    {
        let a = self.extend();
        let mut b = Polynomial::<{ N + 1 }>::new_zero();
        b.set(N, 1);
        b.set(0, (modulus - 1) as i16);

        let (mut old_r, mut r) = (a, b);
        let (mut old_s, mut s) = (Polynomial::new_one(), Polynomial::new_zero());
        let (mut old_t, mut t) = (Polynomial::new_zero(), Polynomial::new_one());

        while !r.zero() {
            let (quo, rem) = old_r.div(r, modulus)?;
            (old_r, r) = (r, old_r.sub(quo.mul(r, modulus), modulus));
            (old_s, s) = (s, old_s.sub(quo.mul(s, modulus), modulus));
            (old_t, t) = (t, old_t.sub(quo.mul(t, modulus), modulus));
        }

        Some(old_s.extend())
    }

    pub fn inverse_prime(self, modulus: u32) -> Option<Self>
    where
        [(); { N + 1 }]:,
    {
        let mut k = 0;
        let mut b = Polynomial::<{ N + 1 }>::new_zero();
        b.set(0, 1);
        let mut c = Polynomial::<{ N + 1 }>::new_zero();

        let mut f = self.normalize(modulus).extend::<{ N + 1 }>();
        let mut g = Polynomial::<{ N + 1 }>::new_zero();
        g.set(0, (modulus - 1) as i16);
        g.set(1, (modulus - 1) as i16);
        g.set(N, 1);

        loop {
            while f.0[0] == 0 {
                f.shift_div_x();
                c.shift_mul_x();

                k += 1;

                if f.zero() {
                    return None;
                }
            }

            if f.degree() == 0 {
                let f0_inv = int_inverse(f.0[0], modulus);
                b = b.mul_scalar(f0_inv, modulus);
                let mut inv = b.reduce(modulus);

                for _ in 0..k {
                    inv.div_x(modulus);
                }

                return Some(inv);
            }

            if f.degree() < g.degree() {
                (f, g) = (g, f);
                (b, c) = (c, b);
            }

            // u = f[0] * g[0]^-1
            let g0_inv = int_inverse(g.0[0], modulus);
            let u = (f.0[0] * g0_inv) % modulus as i16;
            f.sub_multiple(g, u, modulus);
            b.sub_multiple(c, u, modulus);
        }
    }

    pub fn inverse_power_prime(self, p: u8, r: u8) -> Option<Self>
    where
        [(); { N + 1 }]:,
    {
        let mut inv_p = self.normalize(p as u32).inverse_gcd(p as u32)?;

        let count = int_log2(r as i16 + 1);

        let mut two = Polynomial::<N>::new_zero();
        two.set(0, 2);

        let mut q: u32 = p as u32;
        while q < (p as u32).pow(r as u32) as u32 {
            q = q * q;
            inv_p = inv_p.mul(two.sub(self.mul(inv_p, q), q), q);
        }

        Some(inv_p)
    }

    pub fn encode<const MOD: i16>(data: &[u8]) -> Vec<Polynomial<N>> {
        let mut out_polys = vec![];

        let bits_per_coeff = int_log2(MOD);
        let mask = u32::MAX >> (32 - bits_per_coeff);

        let mut byte_idx = 0;
        let mut bit_idx = 0;
        let mut coeff_buf: u32 = 0;
        let mut coeff_bits = 0;
        let mut coeff_idx = 0;

        'outer: loop {
            let mut poly_data: [i16; N] = [0; N];
            while coeff_idx < N {
                while (coeff_bits < bits_per_coeff) {
                    if byte_idx == data.len() {
                        poly_data[coeff_idx] = coeff_buf as i16;
                        out_polys.push(Polynomial(poly_data));
                        break 'outer;
                    }
                    coeff_buf += ((data[byte_idx]) as u32) << coeff_bits;
                    coeff_bits += 8 - bit_idx;
                    byte_idx += 1;
                    bit_idx = 0;
                }

                poly_data[coeff_idx] = (coeff_buf as u32 & mask) as i16;
                coeff_idx += 1;
                coeff_buf >>= bits_per_coeff;
                coeff_bits -= bits_per_coeff;
            }
            out_polys.push(Polynomial(poly_data));
            coeff_idx = 0;
        }
        return out_polys;
    }

    pub fn decode<const MOD: i16>(data: &[Polynomial<N>]) -> Vec<u8> {
        let mut out_bytes = Vec::with_capacity(data.len() * N * int_log2(MOD) as usize / 8 + 1);

        let bits_per_coeff = int_log2(MOD);

        let mut coeff_buf: u32 = 0;
        let mut coeff_bits = 0;
        let mut coeff_idx = 0;

        for p in data.iter() {
            let p = p.normalize(MOD as u32); // ensures all coefficients are positive and 0 <= C < MOD
            while coeff_idx < N {
                while (coeff_bits < 8) {
                    coeff_buf |= ((p.0[coeff_idx] as u32) << coeff_bits);
                    coeff_bits += bits_per_coeff;
                    coeff_idx += 1;
                    if coeff_idx == N {
                        break;
                    }
                }

                while (coeff_bits >= 8) {
                    let mut data = (coeff_buf & 0xFF) as u8;
                    out_bytes.push(data);
                    coeff_buf >>= 8;
                    coeff_bits -= 8;
                }
            }
            coeff_idx = 0;
        }
        if coeff_bits > 0 {
            out_bytes.push((coeff_buf & 0xFF) as u8); // should be at most 1 byte left
        }

        out_bytes
    }
}

pub fn int_log2(mut a: i16) -> i16 {
    let mut log = 0;
    while (a > 1) {
        a /= 2;
        log += 1;
    }
    log
}

pub fn int_inverse(mut n: i16, modulus: u32) -> i16 {
    let mut x = 0;
    let mut x_prev = 1;
    let mut y = 1;
    let mut y_prev = 0;
    let mut b = modulus as i16;
    while b != 0 {
        let q = n / b;

        let mut t = n;
        n = b;
        b = t % b;

        t = x;
        x = x_prev - q * x;
        x_prev = t;

        t = y;
        y = y_prev - q * y;
        y_prev = t;
    }

    if (x_prev < 0) {
        x_prev += modulus as i16;
    }

    x_prev
}

impl<const N: usize> Display for Polynomial<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.zero() {
            return write!(f, "0");
        }
        let mut fst = true;
        for i in 0..N {
            if self.0[i] == 0 {
                continue;
            }
            let pl = match (fst, self.0[i] != -1) {
                (true, true) => "",
                (true, false) => "-",
                (false, true) => " + ",
                (false, false) => " - ",
            };
            let coeff = if (self.0[i] == 1 || self.0[i] == -1) && i != 0 {
                String::new()
            } else {
                format!("{}", self.0[i].abs())
            };
            let xi = if i == 0 {
                String::new()
            } else if i == 1 {
                String::from("X")
            } else {
                format!("X^{}", i)
            };
            write!(f, "{pl}{coeff}{xi}")?;
            fst = false;
        }
        Ok(())
    }
}

impl<const N: usize> Debug for Polynomial<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for i in 0..(N - 1) {
            write!(f, "{:2}, ", self.0[i])?;
        }
        write!(f, "{:2}]", self.0[N - 1])
    }
}
