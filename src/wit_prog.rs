use bech32::Bech32;
use super::CodingError;
use super::AddressError;
use super::ScriptPubKeyError;
use super::BitConversionError;
use super::WitnessProgramError;

/// Witness version and program data
#[derive(PartialEq, Debug, Clone)]
pub struct WitnessProgram {
    pub version: u8,
    pub program: Vec<u8>
}

type EncodeResult = Result<String, AddressError>;
type DecodeResult = Result<WitnessProgram, AddressError>;
type PubKeyResult = Result<WitnessProgram, ScriptPubKeyError>;
type ValidationResult = Result<(), WitnessProgramError>;

impl WitnessProgram {
    pub fn to_address(&self, hrp: String) -> EncodeResult {
        // Verify that the program is valid
        let val_result = self.validate();
        if val_result.is_err() {
            return Err(AddressError::WitnessProgram(val_result.unwrap_err()))
        }
        let mut data: Vec<u8> = vec![self.version];
        // Convert 8-bit program into 5-bit
        let p5 = match convert_bits(self.program.to_vec(), 8, 5, true) {
            Ok(p) => p,
            Err(e) => return Err(AddressError::Conversion(e))
        };
        // let p5 = convert_bits(self.program.to_vec(), 8, 5, true)?;
        data.extend_from_slice(&p5);
        let b32 = Bech32 {hrp: hrp.clone(), data: data};
        let address = match b32.to_string() {
            Ok(s) => s,
            Err(e) => return Err(AddressError::Bech32(e))
        };
        // Ensure that the address decodes into a program properly
        WitnessProgram::from_address(hrp, address.clone())?;
        Ok(address)
    }

    /// Decodes a segwit address into a Witness Program
    ///
    /// Verifies that the `address` contains the expected human-readable part 
    /// `hrp` and decodes as proper Bech32-encoded string. Allowed values of
    /// the human-readable part are 'bc' and 'tb'.
    pub fn from_address(hrp: String, address: String) -> DecodeResult {
        if hrp != "bc".to_string() && hrp != "tb".to_string() {
            return Err(AddressError::InvalidHumanReadablePart)
        }
        let b32 = match Bech32::from_string(address) {
            Ok(b) => b,
            Err(e) => return Err(AddressError::Bech32(e)),
        };
        if b32.hrp != hrp {
            return Err(AddressError::HumanReadableMismatch)
        }
        if b32.data.len() == 0 || b32.data.len() > 65 {
            return Err(AddressError::Bech32(CodingError::InvalidLength))
        }
        // Get the script version and 5-bit program
        let (v, p5) = b32.data.split_at(1);
        let wp = WitnessProgram {
            version: v.to_vec()[0],
            // Convert to 8-bit program and assign
            program: match convert_bits(p5.to_vec(), 5, 8, false) {
                Ok(p) => p,
                Err(e) => return Err(AddressError::Conversion(e))
            }
        };
        match wp.validate() {
            Ok(_) => Ok(wp),
            Err(e) => Err(AddressError::WitnessProgram(e))
        }
    }

    /// Converts a `WitnessProgram` to a script public key
    ///
    /// The format for the output is 
    /// `[version, program length, <program>]`
    pub fn to_scriptpubkey(&self) -> Vec<u8> {
        let mut pubkey: Vec<u8> = Vec::new();
        let mut v = self.version;
        if v > 0 {
            v += 0x50;
        }
        pubkey.push(v);
        pubkey.push(self.program.len() as u8);
        pubkey.extend_from_slice(&self.program);
        pubkey
    }

    /// Extracts a WitnessProgram out of a provided script public key
    pub fn from_scriptpubkey(pubkey: &[u8]) -> PubKeyResult {
        // We need a version byte and a program length byte, with a program at 
        // least 2 bytes long.
        if pubkey.len() < 4 {
            return Err(ScriptPubKeyError::TooShort)
        }
        let proglen: usize = pubkey[1] as usize;
        // Check that program length byte is consistent with pubkey length
        if pubkey.len() != 2 + proglen {
            return Err(ScriptPubKeyError::InvalidLengthByte)
        }
        // Process script version
        let mut v: u8 = pubkey[0];
        if v > 0x50 {
            v -= 0x50;
        }
        let program = &pubkey[2..];
        Ok(WitnessProgram {
            version: v,
            program: program.to_vec()
        })
    }

    /// Validates the WitnessProgram against version and length constraints
    pub fn validate(&self) -> ValidationResult {
        if self.version > 16 {
            // Invalid script version
            return Err(WitnessProgramError::InvalidScriptVersion)
        }
        if self.program.len() < 2 || self.program.len() > 40 {
            return Err(WitnessProgramError::InvalidLength)
        }
        // Check proper script length
        if self.version == 0 && 
                self.program.len() != 20 && self.program.len() != 32 {
            return Err(WitnessProgramError::InvalidVersionLength)
        }
        Ok(())
    }
}

type ConvertResult = Result<Vec<u8>, BitConversionError>;

/// Convert between bit sizes
///
/// # Panics
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is larger than 8 bits.
fn convert_bits(data: Vec<u8>, from: u32, to: u32, pad: bool) -> ConvertResult {
    if from > 8 || to > 8 {
        panic!("convert_bits `from` and `to` parameters greater than 8");
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: Vec<u8> = Vec::new();
    let maxv: u32 = (1<<to) - 1;
    for value in data {
        let v: u32 = value as u32;
        if (v >> from) != 0 {
            // Input value exceeds `from` bit size
            return Err(BitConversionError::InvalidInputValue(v as u8))
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(BitConversionError::InvalidPadding)
    }
    Ok(ret)
}
