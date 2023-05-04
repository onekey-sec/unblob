pub fn shannon_entropy(data: &[u8]) -> f64 {
    let mut entropy = 0.0;
    let mut counts = [0; 256];

    for &b in data {
        counts[b as usize] += 1;
    }

    for &count in &counts {
        if count == 0 {
            continue;
        }

        let p = count as f64 / data.len() as f64;
        entropy -= p * p.log2();
    }

    entropy
}

#[cfg(test)]
mod tests {
    use approx::assert_relative_eq;

    use super::*;

    #[test]
    fn test_shannon_entropy() {
        let input = b"000111"; // 50% entropy distribution ~ 1 bit information

        assert_relative_eq!(shannon_entropy(input), 1.0);
    }
}
