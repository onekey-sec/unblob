use std::io::{Read, Result, Seek, SeekFrom};

const BLOCK_HEADER: u64 = 0x0000_3141_5926_5359;
const BLOCK_ENDMARK: u64 = 0x0000_1772_4538_5090;

const COMPRESSED_MAGIC_LENGTH: u64 = 6 * 8;

pub fn bzip2_recover(mut file: impl Read + Seek, start_offset: u64) -> Result<Option<u64>> {
    let mut bits_read = 0;
    let mut buff = 0;
    let mut blocks_found = 0;
    let mut current_block_end = 0;

    file.seek(SeekFrom::Start(start_offset))?;

    let mut io_buff = vec![0; 1 << 16];

    while let Ok(read) = file.read(&mut io_buff) {
        if read == 0 {
            break;
        }

        for byte in &io_buff[0..read] {
            for offset in (0..=7).rev() {
                bits_read += 1;
                buff = (buff << 1 | ((byte >> offset) & 1) as u64) & 0xFFFF_FFFF_FFFF;

                if buff == BLOCK_HEADER || buff == BLOCK_ENDMARK {
                    blocks_found += 1;
                    current_block_end = bits_read;
                }
            }
        }
    }
    if blocks_found < 2 {
        return Ok(None);
    }

    let end_block_offset = bits_to_bytes(current_block_end);
    Ok(Some(start_offset + end_block_offset))
}


fn bits_to_bytes(number: u64) -> u64 {
    let rounded_up = (number + 7) & !7;

    rounded_up >> 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_to_bytes() {
        assert_eq!(bits_to_bytes(0b0), 0);
        assert_eq!(bits_to_bytes(0b1), 1);
        assert_eq!(bits_to_bytes(0b0100_0000), 8);
        assert_eq!(bits_to_bytes(0b1000_0000), 16);
        assert_eq!(bits_to_bytes(0b1111_1111), 32);
        assert_eq!(bits_to_bytes(0b1_0000_0000), 32);
    }
}
