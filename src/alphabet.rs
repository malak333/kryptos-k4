use anyhow::{Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlphabetKind {
    Standard,
    Kryptos,
    KryptosReversed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alphabet {
    pub kind: AlphabetKind,
    pub symbols: String,
}

impl Alphabet {
    pub fn standard() -> Self {
        Self {
            kind: AlphabetKind::Standard,
            symbols: "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string(),
        }
    }

    pub fn kryptos() -> Self {
        Self {
            kind: AlphabetKind::Kryptos,
            symbols: "KRYPTOSABCDEFGHIJLMNQUVWXZ".to_string(),
        }
    }

    pub fn kryptos_reversed() -> Self {
        let symbols: String = Self::kryptos().symbols.chars().rev().collect();
        Self {
            kind: AlphabetKind::KryptosReversed,
            symbols,
        }
    }

    pub fn all_supported() -> Vec<Self> {
        vec![Self::standard(), Self::kryptos(), Self::kryptos_reversed()]
    }

    pub fn index_of(&self, value: char) -> Result<u8> {
        let upper = value.to_ascii_uppercase();
        self.symbols
            .chars()
            .position(|symbol| symbol == upper)
            .map(|index| index as u8)
            .ok_or_else(|| anyhow::anyhow!("character {value} is not in {:?}", self.kind))
    }

    pub fn char_at(&self, index: u8) -> Result<char> {
        if index >= 26 {
            bail!("alphabet index {index} out of range");
        }

        Ok(self
            .symbols
            .chars()
            .nth(index as usize)
            .expect("validated alphabet index"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kryptos_alphabet_matches_sculpture_order() {
        let alphabet = Alphabet::kryptos();

        assert_eq!(alphabet.index_of('K').unwrap(), 0);
        assert_eq!(alphabet.index_of('R').unwrap(), 1);
        assert_eq!(alphabet.index_of('Z').unwrap(), 25);
        assert_eq!(alphabet.char_at(11).unwrap(), 'E');
    }
}
