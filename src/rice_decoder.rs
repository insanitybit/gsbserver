// Taken from the Golang reference implementation for GSB

use errors::*;

pub struct RiceDecoder<'a> {
    br: BitReader<'a>,
    k: u32, // Golomb-Rice parameter
}
struct BitReader<'a> {
    buf: &'a [u8],
    mask: u8,
}

impl<'a> RiceDecoder<'a> {
    pub fn new(&mut self, buf: &'a [u8], k: u32) -> RiceDecoder<'a> {
        RiceDecoder {
            br: BitReader {
                buf: buf,
                mask: 0x01,
            },
            k: k,
        }
    }

    pub fn read_value(&mut self) -> Result<u32> {
        let mut q = 0;

        loop {
            let bit = try!(self.br.read_bits(1));
            if bit == 0 {
                break;
            }
            q += bit;
        }
        let r = try!(self.br.read_bits(self.k));

        Ok(q << self.k + r)
    }
}
impl<'a> BitReader<'a> {
    pub fn read_bits(&mut self, n: u32) -> Result<u32> {

        if n > 32 {
            return Err(());
        }

        let mut v = 0;

        for i in 0..n {
            if self.buf.len() == 0 {
                return Err(());
            }

            if self.buf[0] & self.mask > 0 {
                v |= 1 << i
            }

            self.mask <<= 1;

            if self.mask == 0 {
                self.buf = &self.buf[1..];
                self.mask = 0x01;
            }
        }
        return Ok(v);
    }

    // BitsRemaining reports the number of bits left to read.
    fn bits_remaining(&self) -> u32 {
        let mut n = 8 * self.buf.len() as u32;

        let mut m = self.mask | 1;
        loop {
            if m != 1 {
                break;
            }
            n = n - 1;
            m >>= 1;
        }

        n
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn it_works() {}
}
