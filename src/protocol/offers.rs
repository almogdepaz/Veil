use serde::{Deserialize, Serialize};
use super::structures::ProtocolError;

/// conditional offer data structure
/// maker publishes this to create an unlinkable offer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalOffer {
    /// conditional spend proof (proves coin burn without updating state)
    pub conditional_proof: Vec<u8>,

    /// amount maker is offering
    pub offered_amount: u64,

    /// amount maker requests in payment
    pub requested_amount: u64,

    /// maker's ecdh public key for receiving payment (stored as vec for serde)
    #[serde(with = "pubkey_serde")]
    pub maker_payment_pubkey: [u8; 33],

    /// optional metadata for orderbook discovery
    pub metadata: Option<OfferMetadata>,
}

// custom serde for [u8; 33] (ec compressed point)
mod pubkey_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.to_vec().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("invalid pubkey length, expected 33 bytes"))
    }
}

/// optional metadata for offer discovery and filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferMetadata {
    /// type of asset being offered (e.g., "token_type_a")
    pub offered_asset_type: String,

    /// type of asset being requested (e.g., "token_type_b")
    pub requested_asset_type: String,

    /// human-readable description
    pub description: String,

    /// optional expiration block height
    pub expires_at: Option<u64>,
}

impl ConditionalOffer {
    pub fn new(
        conditional_proof: Vec<u8>,
        offered_amount: u64,
        requested_amount: u64,
        maker_payment_pubkey: [u8; 33],
    ) -> Self {
        Self {
            conditional_proof,
            offered_amount,
            requested_amount,
            maker_payment_pubkey,
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: OfferMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// extract nullifier from conditional proof public outputs
    /// the nullifier is the first public output in the proof
    pub fn get_nullifier(&self) -> Result<[u8; 32], ProtocolError> {
        // TODO: implement actual proof output extraction
        // for now, this is a placeholder that will be implemented
        // when we add structured proof output format
        Err(ProtocolError::ProofExtractionFailed(
            "nullifier extraction not yet implemented".to_string()
        ))
    }

    /// check if offer is still available (nullifier not in set)
    pub fn is_available(&self, nullifier_set: &std::collections::HashSet<[u8; 32]>) -> Result<bool, ProtocolError> {
        let nullifier = self.get_nullifier()?;
        Ok(!nullifier_set.contains(&nullifier))
    }

    /// get amount that was burned in conditional proof
    /// extracted from proof public outputs
    pub fn get_burned_amount(&self) -> Result<u64, ProtocolError> {
        // TODO: implement actual proof output extraction
        Err(ProtocolError::ProofExtractionFailed(
            "amount extraction not yet implemented".to_string()
        ))
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.conditional_proof.is_empty() {
            return Err(ProtocolError::ProofGenerationFailed(
                "conditional proof cannot be empty".to_string()
            ));
        }

        if self.offered_amount == 0 {
            return Err(ProtocolError::InvalidSpendSecret(
                "offered amount must be > 0".to_string()
            ));
        }

        if self.requested_amount == 0 {
            return Err(ProtocolError::InvalidSpendSecret(
                "requested amount must be > 0".to_string()
            ));
        }

        if self.maker_payment_pubkey == [0u8; 33] {
            return Err(ProtocolError::InvalidSpendSecret(
                "maker payment pubkey cannot be all zeros".to_string()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_offer_creation() {
        let proof = vec![0x01, 0x02, 0x03];
        let pubkey = [0x42; 33];

        let offer = ConditionalOffer::new(proof.clone(), 500, 1000, pubkey);

        assert_eq!(offer.conditional_proof, proof);
        assert_eq!(offer.offered_amount, 500);
        assert_eq!(offer.requested_amount, 1000);
        assert_eq!(offer.maker_payment_pubkey, pubkey);
        assert!(offer.metadata.is_none());
    }

    #[test]
    fn test_offer_with_metadata() {
        let proof = vec![0x01, 0x02, 0x03];
        let pubkey = [0x42; 33];
        let metadata = OfferMetadata {
            offered_asset_type: "USDC".to_string(),
            requested_asset_type: "ETH".to_string(),
            description: "swap usdc for eth".to_string(),
            expires_at: Some(100000),
        };

        let offer = ConditionalOffer::new(proof, 500, 1000, pubkey)
            .with_metadata(metadata);

        assert!(offer.metadata.is_some());
        let meta = offer.metadata.unwrap();
        assert_eq!(meta.offered_asset_type, "USDC");
        assert_eq!(meta.requested_asset_type, "ETH");
    }

    #[test]
    fn test_offer_validation() {
        let valid_offer = ConditionalOffer::new(
            vec![0x01, 0x02],
            500,
            1000,
            [0x42; 33]
        );
        assert!(valid_offer.validate().is_ok());

        let invalid_offer = ConditionalOffer::new(
            vec![],
            500,
            1000,
            [0x42; 33]
        );
        assert!(invalid_offer.validate().is_err());

        let invalid_offer = ConditionalOffer::new(
            vec![0x01],
            0,
            1000,
            [0x42; 33]
        );
        assert!(invalid_offer.validate().is_err());
    }
}
