//! # TODO: Example Regex Precompile https://github.com/ethereum/EIPs/issues/125
//!
//! This module implements a regex precompile for educational purposes.
//! It allows matching a regex pattern against a string and returns the matched substring.

use crate::addresses::REGEX_MATCH_ADDRESS;
use alloy_primitives::Bytes;
use regex::bytes::Regex;
use reth_revm::{
    precompile::{u64_to_address, Precompile, PrecompileWithAddress},
    primitives::{PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult},
};

// TODO UNSAFE: Regex crate is max O(m * n) complexity, need to update gas logic to prevent DoS
/// Base gas fee for the regex match operation.
const REGEXMATCH_BASE: u64 = 3_000;
/// Gas cost per byte of the pattern and string.
const PER_BYTE_GAS_COST: u64 = 10;
/// Gas cost per byte of the output matched substring.
const PER_BYTE_OUTPUT_GAS_COST: u64 = 5;

/// Maximum allowed length for the pattern
const MAX_PATTERN_LENGTH: usize = 255;
/// Maximum allowed length for the string.
const MAX_STRING_LENGTH: usize = 255;
/// Maximum allowed length for the output matched substring.
const MAX_OUTPUT_LENGTH: usize = 255;

/// Returns the regex match precompile with its address.
pub fn precompiles() -> impl Iterator<Item = PrecompileWithAddress> {
    [REGEX_MATCH].into_iter()
}

/// Regex match precompile.
pub const REGEX_MATCH: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(REGEX_MATCH_ADDRESS),
    Precompile::Standard(regex_match),
);

/// Regex match precompile logic.
///
/// The input is encoded as follows:
///
/// | pattern length (u8) | pattern | string length (u8) | string |
/// | :-----------------: | :-----: | :----------------: | :----: |
/// |          1          |   N     |          1         |   M    |
///
/// The output is encoded as:
///
/// | match found (bool, 1 byte) | matched substring length (u8) | matched substring |
/// | :------------------------: | :---------------------------: | :---------------: |
/// |            1               |              1                |         L         |
fn regex_match(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    // Check if input has at least two length fields (1 byte each)
    if input.len() < 2 {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())));
    }

    let mut offset = 0;

    let pattern_length = input[offset] as usize;
    offset += 1;

    if pattern_length > MAX_PATTERN_LENGTH {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())));
    }

    if input.len() < offset + pattern_length {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())));
    }

    let pattern_bytes = &input[offset..offset + pattern_length];
    offset += pattern_length;

    if input.len() < offset + 1 {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())));
    }

    let string_length = input[offset] as usize;
    offset += 1;

    if string_length > MAX_STRING_LENGTH {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())));
    }

    if input.len() < offset + string_length {
        return Err(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())));
    }

    let string_bytes = &input[offset..offset + string_length];

    let total_input_bytes = pattern_length
        .checked_add(string_length)
        .ok_or(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())))? as u64;

    let mut gas_used = REGEXMATCH_BASE
        .checked_add(PER_BYTE_GAS_COST.checked_mul(total_input_bytes).unwrap_or(0))
        .ok_or(PrecompileErrors::Error(PrecompileError::OutOfGas))?;

    let pattern_str = std::str::from_utf8(pattern_bytes)
        .map_err(|_| PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())))?;

    let re = Regex::new(pattern_str)
        .map_err(|_| PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())))?;

    let match_option = re.find(string_bytes);

    let is_match = match_option.is_some();

    let mut output = Vec::new();
    output.push(is_match as u8);

    if let Some(matched) = match_option {
        let matched_bytes = matched.as_bytes();
        let matched_length = matched_bytes.len();

        if matched_length > MAX_OUTPUT_LENGTH {
            return Err(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())));
        }

        gas_used = gas_used
            .checked_add(
                PER_BYTE_OUTPUT_GAS_COST
                    .checked_mul(matched_length as u64)
                    .unwrap_or(0),
            )
            .ok_or(PrecompileErrors::Error(PrecompileError::OutOfGas))?;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        output.push(matched_length as u8);
        output.extend_from_slice(matched_bytes);
    } else {
        output.push(0u8);
    }

    let out = PrecompileOutput::new(gas_used, Bytes::from(output));
    Ok(out)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::hex::FromHex;

    #[test]
    fn test_regex_match_success() {
        // Pattern: b"hello (\x77+)"
        // String: b"hello wwworld"
        let pattern = b"hello (\\x77+)";
        let string = b"hello wwworld";
        let input = prepare_input(pattern, string);

        let gas_limit = 100_000u64;
        let PrecompileOutput { gas_used, bytes } = regex_match(&input, gas_limit).unwrap();

        let total_input_bytes = (pattern.len() + string.len()) as u64;
        let matched_substring = b"hello www";
        let expected_gas = REGEXMATCH_BASE
            + PER_BYTE_GAS_COST * total_input_bytes
            + PER_BYTE_OUTPUT_GAS_COST * (matched_substring.len() as u64);
        assert_eq!(gas_used, expected_gas);

        // Check the result
        assert_eq!(bytes[0], 1); // Match found
        let matched_length = bytes[1] as usize;
        assert_eq!(matched_length, matched_substring.len());
        let extracted = &bytes[2..2 + matched_length];
        assert_eq!(extracted, matched_substring);
    }

    #[test]
    fn test_regex_match_failure() {
        // Pattern: b"^world"
        // String: b"hello world"
        let pattern = b"^world";
        let string = b"hello world";
        let input = prepare_input(pattern, string);

        let gas_limit = 100_000u64;
        let PrecompileOutput { gas_used, bytes } = regex_match(&input, gas_limit).unwrap();

        let total_input_bytes = (pattern.len() + string.len()) as u64;
        let expected_gas = REGEXMATCH_BASE + PER_BYTE_GAS_COST * total_input_bytes;
        assert_eq!(gas_used, expected_gas);

        assert_eq!(bytes[0], 0); // No match found
        let matched_length = bytes[1] as usize;
        assert_eq!(matched_length, 0);
        assert_eq!(bytes.len(), 2); // Only match found byte and length
    }

    #[test]
    fn test_invalid_input_length() {
        // Invalid input (too short)
        let input = Bytes::from_hex("12").unwrap();

        // Set gas limit
        let gas_limit = 10_000u64;
        // Call the precompile
        let result = regex_match(&input, gas_limit);

        // Should return an error
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(PrecompileErrors::Error(PrecompileError::Other("Invalid input".to_string())))
        );
    }

    #[test]
    fn test_out_of_gas() {
        // Pattern: b".*"
        // String: b"test"
        let pattern = b".*";
        let string = b"test";
        let input = prepare_input(pattern, string);

        // Set insufficient gas limit
        let gas_limit = 1u64;
        // Call the precompile
        let result = regex_match(&input, gas_limit);

        // Should return an out of gas error
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(PrecompileErrors::Error(PrecompileError::OutOfGas))
        );
    }

    /// Helper function to prepare the input bytes for the precompile.
    fn prepare_input(pattern: &[u8], string: &[u8]) -> Bytes {
        let mut input = Vec::new();

        // Pattern length as 1-byte u8
        let pattern_length = pattern.len() as u8;
        input.push(pattern_length);

        // Pattern bytes
        input.extend_from_slice(pattern);

        // String length as 1-byte u8
        let string_length = string.len() as u8;
        input.push(string_length);

        // String bytes
        input.extend_from_slice(string);

        Bytes::from(input)
    }
}
