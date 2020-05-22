use vrf::{VRF, openssl::ECVRF};
use statrs::distribution::{Binomial, Univariate};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

type PublicKey<'a> = &'a [u8];
type SecretKey<'a> = &'a [u8];

fn get_largest(length: usize) -> BigUint {
    let length = length * 2;
    let fs = std::iter::once('f').cycle().take(length).collect::<String>();
    let largest = BigUint::parse_bytes(fs.as_bytes(), 16).unwrap() + (1 as u32);

    return largest;
}

fn lottery(hash: std::vec::Vec<u8>, threshold: f64, money: u64, total_money: u64) -> u64 {
    let p = threshold / (total_money as f64);
    let dist = Binomial::new(p, money).unwrap();

    let num = BigUint::from_bytes_be(&hash).to_f64().unwrap();
    let denom = get_largest(hash.len()).to_f64().unwrap();
    let ratio = num / denom;
    
    for i in 0..money {
        let boundary = dist.cdf(i as f64);

        if ratio <= boundary {
            return i;
        } 
    }

    return money;
}

pub fn check_select(sk: SecretKey, seed: &[u8], threshold: f64, // TODO: add a role: int parameter
                    money: u64, total_money: u64, vrf: &mut ECVRF) -> (u64, std::vec::Vec<u8>) {

    let pi = vrf.prove(&sk, &seed).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();
    
    let lottery_num = lottery(hash, threshold, money, total_money);

    return (lottery_num, pi);
}

pub fn verify_select(pk: PublicKey, pi: std::vec::Vec<u8>, seed: &[u8], vrf: &mut ECVRF) -> u64 {

    let beta = vrf.verify(&pk, &pi, &seed);
    
    match beta {
        Ok(beta) => {
            return 1;
        }
        
        Err(e) => {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vrf::openssl::{CipherSuite, ECVRF};
    use hex;
    use uuid::Uuid;
    use num_bigint::ToBigUint;
    
    #[test]
    fn get_largest_test() {
        for i in 1..8 {
            assert_eq!(get_largest(i), (2u64.pow(8 * (i as u32))).to_biguint().unwrap());
        }
    }

    #[test]
    fn test_selection_probability() {
        let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).expect("VRF should init");
         // change this to random number
        let total_money: u64 = 1000000;
        
        // change this to random number
        let t_percentage = 0.5;
        let threshold: f64 = t_percentage * (total_money as f64);
        
         // change this to random number
        let money: u64 = 500000;
        let m_percentage = (money as f64) / (total_money as f64);

        let secret_key = Uuid::new_v4().as_bytes().clone();
        let public_key = vrf.derive_public_key(&secret_key).unwrap();

        let seed: &[u8] = b"random_seed";
        let (practical, pi) = check_select(&secret_key, seed, threshold, money, total_money, &mut vrf);
        let theory = t_percentage * m_percentage * (total_money as f64);

        // this should be an average
        println!("{} {}", practical, theory);
        assert!(((practical as f64)- theory).abs() <= 0.01 * theory);

        // abstract this out
        assert_eq!(verify_select(&public_key, pi, seed, &mut vrf), 1);
    }

    #[test]
    fn playground() {
        let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).expect("VRF should init");
        let secret_key =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        let public_key = vrf.derive_public_key(&secret_key).unwrap();

        let seed: &[u8] = b"random_seed";

         // VRF proof and hash output
        let pi = vrf.prove(&secret_key, &seed).unwrap();
        let hash = vrf.proof_to_hash(&pi).unwrap();
        let num = BigUint::from_bytes_be(&hash);
        let fatty = get_largest(1);

        println!("Length: {}", hash.len());
        println!("Big Int: {}", num);
        println!("Hash: {}", hex::encode(&hash));
        println!("Largest Num: {}", fatty);
        println!("Generated VRF proof: {}", hex::encode(&pi));
    }
}