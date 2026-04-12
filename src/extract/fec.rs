/// Android FEC constants.
pub const FEC_RSM: u32 = 255;
/// Android FEC block size.
pub const FEC_BLOCKSIZE: u64 = 4096;

const GF_POLY: u32 = 0x11d;
const PRIM: usize = 1;
const NN: usize = 255; // (1 << 8) - 1

/// Reed-Solomon codec for GF(2^8).
pub struct RsEncoder {
    alpha_to: [u8; 256],
    index_of: [u8; 256],
    genpoly: Vec<u8>, // in index form, length = nroots + 1
    nroots: usize,
}

#[inline]
fn modnn(x: usize) -> usize {
    let mut v = x;
    while v >= NN {
        v -= NN;
        v = (v >> 8) + (v & NN);
    }
    v
}

// Index-based loops match the canonical RS algorithm structure and are clearer
// than iterator chains for this use case.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
impl RsEncoder {
    /// Create a new RS encoder with the given number of roots (parity symbols).
    pub fn new(nroots: usize) -> Self {
        assert!(nroots > 0 && nroots < NN);

        // Build GF(2^8) lookup tables
        let mut alpha_to = [0u8; 256];
        let mut index_of = [0u8; 256];

        index_of[0] = NN as u8; // A0 = log(0) = -inf encoded as NN
        alpha_to[NN] = 0; // alpha^(-inf) = 0

        let mut sr: u32 = 1;
        for i in 0..NN {
            index_of[sr as usize] = i as u8;
            alpha_to[i] = sr as u8;
            sr <<= 1;
            if sr & (1 << 8) != 0 {
                sr ^= GF_POLY;
            }
            sr &= NN as u32;
        }

        // Build generator polynomial (fcr=0, prim=1)
        let mut genpoly = vec![0u8; nroots + 1];
        genpoly[0] = 1;

        let mut root = 0; // FCR * PRIM = 0
        for i in 0..nroots {
            genpoly[i + 1] = 1;
            for j in (1..=i).rev() {
                if genpoly[j] != 0 {
                    genpoly[j] = genpoly[j - 1]
                        ^ alpha_to[modnn(index_of[genpoly[j] as usize] as usize + root)];
                } else {
                    genpoly[j] = genpoly[j - 1];
                }
            }
            genpoly[0] = alpha_to[modnn(index_of[genpoly[0] as usize] as usize + root)];
            root += PRIM;
        }

        // Convert to index form
        for coeff in genpoly.iter_mut() {
            *coeff = index_of[*coeff as usize];
        }

        Self {
            alpha_to,
            index_of,
            genpoly,
            nroots,
        }
    }

    /// Encode `data` (NN - nroots symbols) and write parity into `parity` (nroots symbols).
    pub fn encode(&self, data: &[u8], parity: &mut [u8]) {
        debug_assert_eq!(parity.len(), self.nroots);
        let nn = NN;
        let nroots = self.nroots;
        let data_len = nn - nroots; // pad=0, so data length = NN - NROOTS

        parity.fill(0);

        let len = data.len().min(data_len);
        for &byte in &data[..len] {
            let feedback = self.index_of[(byte ^ parity[0]) as usize];
            if (feedback as usize) != nn {
                // A0 check
                for j in 1..nroots {
                    parity[j] ^=
                        self.alpha_to[modnn(feedback as usize + self.genpoly[nroots - j] as usize)];
                }
            }
            // Shift
            parity.copy_within(1..nroots, 0);
            if (feedback as usize) != nn {
                parity[nroots - 1] =
                    self.alpha_to[modnn(feedback as usize + self.genpoly[0] as usize)];
            } else {
                parity[nroots - 1] = 0;
            }
        }
    }
}

/// Compute interleaved offset for FEC encoding.
#[inline]
pub fn fec_ecc_interleave(offset: u64, rsn: u32, rounds: u64) -> u64 {
    (offset / rsn as u64) + (offset % rsn as u64) * rounds * FEC_BLOCKSIZE
}

/// Compute the FEC data size for a given file size and number of roots.
pub fn fec_ecc_get_data_size(file_size: u64, roots: u32) -> u64 {
    let rsn = FEC_RSM - roots;
    file_size.div_ceil(FEC_BLOCKSIZE).div_ceil(rsn as u64) * roots as u64 * FEC_BLOCKSIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rs_encoder_basic() {
        let rs = RsEncoder::new(2);
        let data = vec![0u8; NN - 2];
        let mut parity = vec![0u8; 2];
        rs.encode(&data, &mut parity);
        // All-zero input should give all-zero parity
        assert_eq!(parity, [0, 0]);
    }

    #[test]
    fn test_rs_encoder_nonzero() {
        let rs = RsEncoder::new(2);
        let mut data = vec![0u8; NN - 2];
        data[0] = 1;
        let mut parity = vec![0u8; 2];
        rs.encode(&data, &mut parity);
        // Non-zero input should give non-zero parity
        assert!(parity != [0, 0]);
    }

    #[test]
    fn test_fec_ecc_interleave() {
        assert_eq!(fec_ecc_interleave(0, 253, 10), 0);
        assert_eq!(fec_ecc_interleave(1, 253, 10), 10 * FEC_BLOCKSIZE);
        assert_eq!(fec_ecc_interleave(253, 253, 10), 1);
    }

    #[test]
    fn test_fec_ecc_get_data_size() {
        // Known values for verification
        let size = fec_ecc_get_data_size(100 * FEC_BLOCKSIZE, 2);
        assert!(size > 0);
        assert_eq!(size % FEC_BLOCKSIZE, 0);
    }
}
