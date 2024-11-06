use pyo3::prelude::*;
use statrs::distribution::{ChiSquared, ContinuousCDF};

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
/// Calculates Shannon entropy of data
#[pyfunction(name = "shannon_entropy")]
pub fn py_shannon_entropy(py: Python, data: &[u8]) -> PyResult<f64> {
    py.allow_threads(|| Ok(shannon_entropy(data)))
}

pub fn chi_square_probability(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Total number of possible byte values (0–255)
    let num_bins = 256;
    let expected_count = data.len() as f64 / num_bins as f64;

    // Frequency count for each byte value
    let mut frequencies = [0u32; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    // Calculate chi-square statistic
    let chi_square: f64 = frequencies
        .iter()
        .map(|&obs| {
            let observed = obs as f64;
            (observed - expected_count).powi(2) / expected_count
        })
        .sum();

    // Degrees of freedom: 255 (256 bins - 1)
    let degrees_of_freedom = (num_bins - 1) as f64;
    let chi_squared = ChiSquared::new(degrees_of_freedom).unwrap();

    // Compute p-value (chi-square probability)
    1.0 - chi_squared.cdf(chi_square)
}
/// Calculates Chi Square of data
#[pyfunction(name = "chi_square_probability")]
pub fn py_chi_square_probability(py: Python, data: &[u8]) -> PyResult<f64> {
    py.allow_threads(|| Ok(chi_square_probability(data)))
}

pub fn init_module(root_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new_bound(root_module.py(), "math_tools")?;
    module.add_function(wrap_pyfunction!(py_shannon_entropy, &module)?)?;
    module.add_function(wrap_pyfunction!(py_chi_square_probability, &module)?)?;

    root_module.add_submodule(&module)?;

    root_module
        .py()
        .import_bound("sys")?
        .getattr("modules")?
        .set_item("unblob_native.math", module)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod shannon {
        use super::*;

        #[test]
        fn test_shannon_entropy() {
            let input = b"000111"; // 50% entropy distribution ~ 1 bit information

            assert_eq!(shannon_entropy(input), 1.0);
        }
    }

    mod chi_square {
        use super::*;
        use rand::prelude::*;

        #[test]
        fn test_non_uniform_distribution() {
            let uniform_distribution = [0u8; 4096];
            let chi_square_value = chi_square_probability(&uniform_distribution);

            assert_eq!(
                chi_square_value, 0.0,
                "Chi-square probability for fully non uniform distributions should be 0.0"
            );
        }

        #[test]
        fn test_uniform_distribution() {
            let uniform_distribution: Vec<u8> = (0..=255).collect();
            let chi_square_value = chi_square_probability(&uniform_distribution);

            assert_eq!(
                chi_square_value, 1.0,
                "Chi-square probability for fully uniform distributions should be 1.0"
            );
        }

        #[test]
        fn test_random_distribution() {
            let mut random_data = [0u8; 4096];
            StdRng::from_entropy().fill_bytes(&mut random_data);
            let chi_square_value = chi_square_probability(&random_data);

            assert!(
                chi_square_value > 0.0 && chi_square_value < 1.0,
                "Chi-square probability for PRNG distribution should be within bounds"
            );
        }

        #[test]
        fn test_empty_data() {
            let empty_data: Vec<u8> = Vec::new();
            let chi_square_value = chi_square_probability(&empty_data);

            assert_eq!(
                chi_square_value, 0.0,
                "Chi-square probability for empty data should be 0.0"
            );
        }
    }
}
