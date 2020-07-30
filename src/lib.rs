#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use bls_sigs_ref::*;
    use pairing_plus::bls12_381::{G1, G2};
    use pairing_plus::hash_to_field::ExpandMsgXmd;
    use std::time::Instant;
    use std::io;
    use std::io::Write;
    use threshold_crypto::{SecretKey, PublicKeySet, PublicKey, SecretKeySet, PublicKeyShare, SecretKeyShare, SignatureShare};
    use std::collections::BTreeMap;

    const CSUITE: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    const ITERATIONS: usize = 7;
    #[test]
    fn signing_poc() {
        let mut rng = thread_rng();

        let mut tk = [0u8; 32];
        let mut message = [0u8; 32];
        rng.fill_bytes(&mut tk);
        rng.fill_bytes(&mut message);

        let (sk, pk) = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::keygen(&tk[..]);
        let sign = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign(sk, message, CSUITE);

        let res = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(pk,sign, message, CSUITE);

        if res {
            println!("Success!");
        } else {
            println!("Fail!");
        }
    }

    #[test]
    fn basics() {
        let mut rng = thread_rng();
        let mut pk_set = Vec::with_capacity(ITERATIONS);
        let mut signatures = Vec::with_capacity(ITERATIONS);
        let mut sk_set = Vec::with_capacity(ITERATIONS);
        let mut results = Vec::with_capacity(ITERATIONS);
        let message = b"Hello World!";

        // Generate keys
        for _ in 0..ITERATIONS {
            let mut tk = [0u8; 32];
            rng.fill_bytes(&mut tk);
            let (sk, pk) = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::keygen(&tk[..]);
            sk_set.push(sk);
            pk_set.push(pk);
        }

        // Sign message
        for key in &sk_set {
            let x_prime = (*key).clone();
            let sig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign(x_prime, message, CSUITE);
            signatures.push(sig);
        }

        // Verify signs
        for i in 0..ITERATIONS {
            let res = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(pk_set[i], signatures[i], message, CSUITE);
            results.push(res);
        }
        assert!(results.iter().all(|t| *t));

        // Multi-sigs
        let aggregated_sign = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(signatures.as_slice());
        let aggregated_pk = <G2 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(pk_set.as_slice());
        assert!(<G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(aggregated_pk, aggregated_sign, message, CSUITE));

        // Aggregation
        let mut messages = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            let msg = format!("Message {} {}", String::from_utf8(message.to_vec()).unwrap(), i);
            let x_prime = sk_set[i].clone();
            let signature = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign( x_prime,  &msg.as_bytes(), CSUITE);
            signatures[i] = signature;
            messages.push(msg);
        }
        signatures.pop();
        let asig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(signatures.as_slice());
        assert!(<G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_aggregate_verify(pk_set.as_slice(), messages.as_slice(), asig, CSUITE));
    }

    #[test]
    fn pairing_plus() {
        let message = b"Hello World!";

        println!("================================================================================");
        println!("BLS ZCash pairing");
        println!("-----------------");
        let mut verkeys = Vec::with_capacity(ITERATIONS);
        let mut signatures = Vec::with_capacity(ITERATIONS);
        let mut signkeys = Vec::with_capacity(ITERATIONS);
        let mut rng = thread_rng();
        for _ in 0..ITERATIONS {
            let mut tk = [0u8; 32];
            rng.fill_bytes(&mut tk);
            let (sk, pk) = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::keygen(&tk[..]);
            signkeys.push(sk);
            verkeys.push(pk);
        }
        print!("Generating - {} signatures...", ITERATIONS);
        io::stdout().flush().unwrap();
        let start = Instant::now();
        for key in &signkeys {
            let x_prime = (*key).clone();
            let sig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign(x_prime, message, CSUITE);
            signatures.push(sig);
        }
        let elapsed = Instant::now() - start;
        println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

        print!("Verifying - {} signatures...", ITERATIONS);
        io::stdout().flush().unwrap();
        let mut results = Vec::with_capacity(ITERATIONS);
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let res = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(verkeys[i], signatures[i], message, CSUITE);
            results.push(res);
        }
        let elapsed = Instant::now() - start;
        println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
        assert!(results.iter().all(|t| *t));

        print!("Verifying - multisignature...");
        io::stdout().flush().unwrap();
        let asig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(signatures.as_slice());
        let apk = <G2 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(verkeys.as_slice());
        let start = Instant::now();
        assert!(<G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(apk, asig, message, CSUITE));
        let elapsed = Instant::now() - start;
        println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

        print!("Verifying - aggregated signature...");
        io::stdout().flush().unwrap();
        let mut messages = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            let msg = format!("Message {} {}", String::from_utf8(message.to_vec()).unwrap(), i);
            let x_prime = signkeys[i].clone();
            let signature = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign( x_prime,  &msg.as_bytes(), CSUITE);
            signatures[i] = signature;
            messages.push(msg);
        }
        let asig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(signatures.as_slice());
        <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_aggregate_verify(verkeys.as_slice(), messages.as_slice(), asig, CSUITE);
        assert!(<G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_aggregate_verify(verkeys.as_slice(), messages.as_slice(), asig, CSUITE));
        let elapsed = Instant::now() - start;
        println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
        println!("================================================================================");
    }

    #[test]
    fn threshold() {
        let message = b"Hello World!";

        println!("================================================================================");
        println!("BLS ZCash pairing");
        println!("-----------------");
        let mut verkeys = Vec::with_capacity(ITERATIONS);
        let mut signatures = Vec::with_capacity(ITERATIONS);
        let mut signkeys = Vec::with_capacity(ITERATIONS);
        let mut rng = thread_rng();
        for _ in 0..ITERATIONS {
            let sk = SecretKey::random();
            let pk = sk.public_key();
            // let mut tk = [0u8; 32];
            // rng.fill_bytes(&mut tk);
            // let (sk, pk) = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::keygen(&tk[..]);
            signkeys.push(sk);
            verkeys.push(pk);
        }
        print!("Generating - {} signatures...", ITERATIONS);
        io::stdout().flush().unwrap();
        let start = Instant::now();
        for key in &signkeys {
            // let x_prime = (*key).clone();
            // let sig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign(x_prime, message, CSUITE);
            let sig = key.sign(message);
            signatures.push(sig);
        }
        let elapsed = Instant::now() - start;
        println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

        print!("Verifying - {} signatures...", ITERATIONS);
        io::stdout().flush().unwrap();
        let mut results = Vec::with_capacity(ITERATIONS);
        let start = Instant::now();
        for i in 0..ITERATIONS {
            // let res = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_verify(verkeys[i], signatures[i], message, CSUITE);
            let res = verkeys[i].verify(&signatures[i], message);
            results.push(res);
        }
        let elapsed = Instant::now() - start;
        println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
        assert!(results.iter().all(|t| *t));

        print!("Verifying - Aggregated Signature...");
        io::stdout().flush().unwrap();
        let sk_set = SecretKeySet::random(6, &mut rng);
        let pk_set = sk_set.public_keys();
        let mut sig_shares: BTreeMap<_, _> = BTreeMap::new();
        for i in 0..ITERATIONS {
            let share = sk_set.secret_key_share(i).sign(message);
            sig_shares.insert(i, share);
        }
        let start = Instant::now();
        let sig = pk_set.combine_signatures(sig_shares.clone()).unwrap();
        let aggregated_pk = pk_set.public_key();
        assert!(aggregated_pk.verify(&sig, message));
        let elapsed = Instant::now() - start;
        println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);

        // print!("Verifying - Multi Signature...");
        // io::stdout().flush().unwrap();
        // let mut messages = Vec::with_capacity(ITERATIONS);
        // for i in 0..ITERATIONS {
        //     let msg = format!("Message {} {}", String::from_utf8(message.to_vec()).unwrap(), i);
        //     let sk_set = SecretKeySet::random(6, &mut rng);
        //     let sk_share = SecretKeyShare::from_mut(sk_set);
        //     let pk_shares = PublicKeyShare
        //     let x_prime = signkeys[i].clone();
        //     let signature = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_sign( x_prime,  &msg.as_bytes(), CSUITE);
        //     signatures[i] = signature;
        //     messages.push(msg);
        // }
        // let asig = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::aggregate(signatures.as_slice());
        // <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_aggregate_verify(verkeys.as_slice(), messages.as_slice(), asig, CSUITE);
        // assert!(<G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::core_aggregate_verify(verkeys.as_slice(), messages.as_slice(), asig, CSUITE));
        // let elapsed = Instant::now() - start;
        // println!("{}.{:0<2}s", elapsed.as_millis() / 1000, (elapsed.as_millis() % 1000) / 10);
        println!("================================================================================");
    }
}
