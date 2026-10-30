// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! Known-answer vectors for the local check of a signature made over a
//! digest (`SpkiDer::verify_digest_signature`): every pairing of key and
//! hash a browser can ask the phone for.
//!
//! ECDSA: RFC 6979 appendix A.2.5 (P-256) and A.2.6 (P-384), message
//! "sample", with SHA-256, SHA-384 and SHA-512 on each curve. RSA: NIST
//! CAVP FIPS 186-3 RSA test vectors, `SigGen15_186-3.txt` (PKCS#1 v1.5,
//! 2048-bit modulus, the first message for each of SHA-256, SHA-384 and
//! SHA-512) and `SigGenPSS_186-3.txt` (PSS, 3072-bit modulus, the first
//! SHA-256 message, whose salt is 32 bytes). Public exponents are written
//! without the files' leading zero padding.

#![allow(
    clippy::unwrap_used,
    reason = "the vectors are fixed and decode by construction"
)]

use refineid_lib_core::oid::{Oid, known};
use refineid_lib_core::x509::{DigestCheckError, MessageSignatureAlgorithm, SpkiDer};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use spki::der::Encode as _;
use spki::der::asn1::{Any, BitString, Null, ObjectIdentifier, UintRef};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// The leading octet of an uncompressed elliptic-curve point (SEC 1
/// version 2 section 2.3.3).
const SEC1_UNCOMPRESSED: u8 = 4;
/// The RFC 6979 appendix A.2 test message.
const RFC6979_MESSAGE: &str = "sample";
/// Members of `RSAPublicKey` (RFC 8017 appendix A.1.1).
const RSA_PUBLIC_KEY_MEMBERS: usize = 2;

/// RFC 6979 A.2.5 public key `Ux`.
const P256_UX: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";

/// RFC 6979 A.2.5 public key `Uy`.
const P256_UY: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

/// RFC 6979 A.2.5, SHA-256, "sample": `r || s`.
const P256_SHA256_RS: &str = "\
efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

/// RFC 6979 A.2.5, SHA-384, "sample": `r || s`.
const P256_SHA384_RS: &str = "\
0eafea039b20e9b42309fb1d89e213057cbf973dc0cfc8f129edddc800ef7719\
4861f0491e6998b9455193e34e7b0d284ddd7149a74b95b9261f13abde940954";

/// RFC 6979 A.2.5, SHA-512, "sample": `r || s`.
const P256_SHA512_RS: &str = "\
8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00\
2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe";

/// RFC 6979 A.2.6 public key `Ux`.
const P384_UX: &str = "\
ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64\
def8f0ea9055866064a254515480bc13";

/// RFC 6979 A.2.6 public key `Uy`.
const P384_UY: &str = "\
8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1\
288b231c3ae0d4fe7344fd2533264720";

/// RFC 6979 A.2.6, SHA-256, "sample": `r || s`.
const P384_SHA256_RS: &str = "\
21b13d1e013c7fa1392d03c5f99af8b30c570c6f98d4ea8e354b63a21d3daa33\
bde1e888e63355d92fa2b3c36d8fb2cdf3aa443fb107745bf4bd77cb38916746\
32068a10ca67e3d45db2266fa7d1feebefdc63eccd1ac42ec0cb8668a4fa0ab0";

/// RFC 6979 A.2.6, SHA-384, "sample": `r || s`.
const P384_SHA384_RS: &str = "\
94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
81a648152e44acf96e36dd1e80fabe4699ef4aeb15f178cea1fe40db2603138f\
130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8";

/// RFC 6979 A.2.6, SHA-512, "sample": `r || s`.
const P384_SHA512_RS: &str = "\
ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a799c\
fe30f35cc900056d7c99cd7882433709512c8cceee3890a84058ce1e22dbc219\
8f42323ce8aca9135329f03c068e5112dc7cc3ef3446defceb01a45c2667fdd5";

/// `SigGen15_186-3.txt`, mod = 2048: `n`.
const PKCS1_N: &str = "\
cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72c\
c516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aef\
b920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a9681\
5b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30\
b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbf\
a2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11\
813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a\
8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d";

/// `SigGen15_186-3.txt`, mod = 2048: `e`.
const PKCS1_E: &str = "260445";

/// `SigGen15_186-3.txt`, mod = 2048, first SHA-256 `Msg`.
const PKCS1_SHA256_MSG: &str = "\
5af283b1b76ab2a695d794c23b35ca7371fc779e92ebf589e304c7f923d8cf97\
6304c19818fcd89d6f07c8d8e08bf371068bdf28ae6ee83b2e02328af8c0e2f9\
6e528e16f852f1fc5455e4772e288a68f159ca6bdcf902b858a1f94789b31638\
23e2d0717ff56689eec7d0e54d93f520d96e1eb04515abc70ae90578ff38d31b";

/// `SigGen15_186-3.txt`, mod = 2048, first SHA-256 `S`.
const PKCS1_SHA256_S: &str = "\
6b8be97d9e518a2ede746ff4a7d91a84a1fc665b52f154a927650db6e7348c69\
f8c8881f7bcf9b1a6d3366eed30c3aed4e93c203c43f5528a45de791895747ad\
e9c5fa5eee81427edee02082147aa311712a6ad5fb1732e93b3d6cd23ffd46a0\
b3caf62a8b69957cc68ae39f9993c1a779599cdda949bdaababb77f248fcfeaa\
44059be5459fb9b899278e929528ee130facd53372ecbc42f3e8de2998425860\
406440f248d817432de687112e504d734028e6c5620fa282ca07647006cf0a2f\
f83e19a916554cc61810c2e855305db4e5cf893a6a96767365794556ff033359\
084d7e38a8456e68e21155b76151314a29875feee09557161cbc654541e89e42";

/// `SigGen15_186-3.txt`, mod = 2048, first SHA-384 `Msg`.
const PKCS1_SHA384_MSG: &str = "\
6cd59fdd3efd893d091afdc3155d354f10d6d88167427a2cf7246207e51791a6\
ca6200a914cd2834a9b3c79fcd59e26e457e0683bc33d49267edbdd6e5d90902\
696f1e7b1a4affc4ba371339868c28015ebbb73e262669866c35db974ba69e46\
8f2583b9191d15d686cd66fb0b9e0ff0a3b4721a6dc342f14f2446b4e028595b";

/// `SigGen15_186-3.txt`, mod = 2048, first SHA-384 `S`.
const PKCS1_SHA384_S: &str = "\
3974900bec3fcb081f0e5a299adf30d087aabaa633911410e87a4979bbe3fa80\
c3abcf221686399a49bc2f1e5ac40c35df1700e4b9cb7c805a896646573f4a57\
0a9704d2a2e6baee4b43d916906884ad3cf283529ea265e8fcb5cc1bdf7b7dee\
85941e4b4fb25c1fc7b951fb129ab393cb069be271c1d954da3c43674309f1d2\
12826fabb8e812de2d53d12597de040d32cb28c9f813159cb18c1b51f7a874cb\
f229cc222caeb98e35ec5e4bf5c5e22cc8528631f15117e8c2be6eac91f4070e\
ecdd07ecc6db6c46eaa65f472f2006988efef0b51c538c6e04d7519c8e3da4b1\
72b1e2761089ed3ad1197992ef37c168dc881c8b5f8bbfee919f7c7afd25b8fc";

/// `SigGen15_186-3.txt`, mod = 2048, first SHA-512 `Msg`.
const PKCS1_SHA512_MSG: &str = "\
a7c309d44a57188bbd7b726b98b98ce12582228e1415864870a23961d2afb82c\
d5bc98bec922d5f2ac4168b056da176ef3ba91f6b699ba6acc4144868ff37f26\
fd06720868d12ad26ecb52572cf10416af68df03ab645a8b704857d2190ffc3f\
07eabe3a8e2abe34ed6159e884c4fae141d4333d5c3e0db044ff9cccd9cbd67f";

/// `SigGen15_186-3.txt`, mod = 2048, first SHA-512 `S`.
const PKCS1_SHA512_S: &str = "\
148af61ed5ea8a87a08b3f403929bf8031db4fd3999b64409ba489f97a3ee520\
8ea4202d2ec18734f615003a51f77441085be6ac0f11810ffa2dad58f0e186d5\
520ac2b8a5d3966e8d2abb8074e13b50a4e7de83be10a66fdc7ca18118c5774f\
781212de9efebc6376fcdddc65a3b1b8f1ab31492fe478259ce719b3db587498\
d879a01dec96e8eabeb07ff7073f3f3eb446084955ca26329a791315a2c259d2\
25e26b2154b2047b21faba68115bfd962e5e24ec52d7c5d231e3044cbcd8c880\
4855703cbaa622b15b6ef78c7421a367166f1b02576c87360593da75b7189efa\
fd1082bd59f6857f1701f646c24d70c95273c49d5b11e6afe258821b55c1680c";

/// `SigGenPSS_186-3.txt`, mod = 3072: `n`.
const PSS_N: &str = "\
a7a1882a7fb896786034d07fb1b9f6327c27bdd7ce6fe39c285ae3b6c34259ad\
c0dc4f7b9c7dec3ca4a20d3407339eedd7a12a421da18f5954673cac2ff05915\
6ecc73c6861ec761e6a0f2a5a033a6768c6a42d8b459e1b4932349e84efd92df\
59b45935f3d0e30817c66201aa99d07ae36c5d74f408d69cc08f044151ff4960\
e531360cb19077833adf7bce77ecfaa133c0ccc63c93b856814569e0b9884ee5\
54061b9a20ab46c38263c094dae791aa61a17f8d16f0e85b7e5ce3b067ece89e\
20bc4e8f1ae814b276d234e04f4e766f501da74ea7e3817c24ea35d016676cec\
e652b823b051625573ca92757fc720d254ecf1dcbbfd21d98307561ecaab5454\
80c7c52ad7e9fa6b597f5fe550559c2fe923205ac1761a99737ca02d7b19822e\
008a8969349c87fb874c81620e38f613c8521f0381fe5ba55b74827dad3e1cf2\
aa29c6933629f2b286ad11be88fa6436e7e3f64a75e3595290dc0d1cd5eee7aa\
ac54959cc53bd5a934a365e72dd81a2bd4fb9a67821bffedf2ef2bd94913de8b";

/// `SigGenPSS_186-3.txt`, mod = 3072: `e`.
const PSS_E: &str = "1415a7";

/// `SigGenPSS_186-3.txt`, mod = 3072, first SHA-256 `Msg`.
const PSS_SHA256_MSG: &str = "\
c16499110ed577202aed2d3e4d51ded6c66373faef6533a860e1934c63484f87\
a8d9b92f3ac45197b2909710abba1daf759fe0510e9bd8dd4d73cec961f06ee0\
7acd9d42c6d40dac9f430ef90374a7e944bde5220096737454f96b614d0f6cdd\
9f08ed529a4ad0e759cf3a023dc8a30b9a872974af9b2af6dc3d111d0feb7006";

/// `SigGenPSS_186-3.txt`, mod = 3072, first SHA-256 `S`.
const PSS_SHA256_S: &str = "\
4335707da735cfd10411c9c048ca9b60bb46e2fe361e51fbe336f9508dc945af\
e075503d24f836610f2178996b52c411693052d5d7aed97654a40074ed20ed66\
89c0501b7fbac21dc46b665ac079760086414406cd66f8537d1ebf0dce4cf0c9\
8d4c30c71da359e9cd401ff49718fdd4d0f99efe70ad8dd8ba1304cefb88f24b\
0eedf70116da15932c76f0069551a245b5fc3b91ec101f1d63b9853b598c6fa1\
c1acdbacf9626356c760119be0955644301896d9d0d3ea5e6443cb72ca29f4d4\
5246d16d74d00568c219182feb191179e4593dc152c608fd80536329a533b3a6\
31566814cd654f587c2d8ce696085e6ed1b0b0278e60a049ec7a399f94fccae6\
462371a69695ef525e00936fa7d9781f9ee289d4105ee827a27996583033cedb\
2f297e7b4926d906ce0d09d84128406ab33d7da0f8a1d4d2f666568686c394d1\
39b0e5e99337758de85910a5fa25ca2aa6d8fb1c777244e7d98de4c79bbd426a\
5e6f657e37477e01247432f83797fbf31b50d02b83f69ded26d4945b2bc3f86e";

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

fn oid(known: Oid<'_>) -> ObjectIdentifier {
    ObjectIdentifier::from_bytes(known.as_bytes()).unwrap()
}

fn spki(algorithm: Oid<'_>, parameters: Any, key: &[u8]) -> Vec<u8> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: oid(algorithm),
            parameters: Some(parameters),
        },
        subject_public_key: BitString::from_bytes(key).unwrap(),
    }
    .to_der()
    .unwrap()
}

/// An `id-ecPublicKey` key on `curve` (RFC 5480 section 2).
fn ec_spki(curve: Oid<'_>, x: &str, y: &str) -> Vec<u8> {
    let mut point = vec![SEC1_UNCOMPRESSED];
    point.extend(bytes(x));
    point.extend(bytes(y));
    spki(
        known::EC_PUBLIC_KEY,
        Any::encode_from(&oid(curve)).unwrap(),
        &point,
    )
}

/// An `rsaEncryption` key (RFC 3279 section 2.3.1).
fn rsa_spki(n: &str, e: &str) -> Vec<u8> {
    let (n, e) = (bytes(n), bytes(e));
    let key: [UintRef<'_>; RSA_PUBLIC_KEY_MEMBERS] =
        [UintRef::new(&n).unwrap(), UintRef::new(&e).unwrap()];
    spki(
        known::RSA_ENCRYPTION,
        Any::encode_from(&Null).unwrap(),
        &key.to_der().unwrap(),
    )
}

fn check(
    spki: &[u8],
    algorithm: MessageSignatureAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), DigestCheckError> {
    SpkiDer::try_from(spki)
        .unwrap()
        .verify_digest_signature(algorithm, digest, signature)
}

/// The three hashes a browser names, with the digest of `message`
/// under each.
fn digests(message: &[u8]) -> [(MessageSignatureAlgorithm, Vec<u8>); 3] {
    [
        (
            MessageSignatureAlgorithm::EcdsaSha256Raw,
            Sha256::digest(message).to_vec(),
        ),
        (
            MessageSignatureAlgorithm::EcdsaSha384Raw,
            Sha384::digest(message).to_vec(),
        ),
        (
            MessageSignatureAlgorithm::EcdsaSha512Raw,
            Sha512::digest(message).to_vec(),
        ),
    ]
}

#[test]
fn p256_signatures_verify_with_every_hash() {
    let key = ec_spki(known::SECP256R1, P256_UX, P256_UY);
    let signatures = [P256_SHA256_RS, P256_SHA384_RS, P256_SHA512_RS];
    for ((algorithm, digest), signature) in digests(RFC6979_MESSAGE.as_bytes())
        .into_iter()
        .zip(signatures)
    {
        assert_eq!(check(&key, algorithm, &digest, &bytes(signature)), Ok(()));
    }
}

#[test]
fn p384_signatures_verify_with_every_hash() {
    let key = ec_spki(known::SECP384R1, P384_UX, P384_UY);
    let signatures = [P384_SHA256_RS, P384_SHA384_RS, P384_SHA512_RS];
    for ((algorithm, digest), signature) in digests(RFC6979_MESSAGE.as_bytes())
        .into_iter()
        .zip(signatures)
    {
        assert_eq!(check(&key, algorithm, &digest, &bytes(signature)), Ok(()));
    }
}

#[test]
fn rsa_pkcs1_signatures_verify_with_every_hash() {
    let key = rsa_spki(PKCS1_N, PKCS1_E);
    let cases = [
        (
            MessageSignatureAlgorithm::RsaPkcs1Sha256,
            Sha256::digest(bytes(PKCS1_SHA256_MSG)).to_vec(),
            PKCS1_SHA256_S,
        ),
        (
            MessageSignatureAlgorithm::RsaPkcs1Sha384,
            Sha384::digest(bytes(PKCS1_SHA384_MSG)).to_vec(),
            PKCS1_SHA384_S,
        ),
        (
            MessageSignatureAlgorithm::RsaPkcs1Sha512,
            Sha512::digest(bytes(PKCS1_SHA512_MSG)).to_vec(),
            PKCS1_SHA512_S,
        ),
    ];
    for (algorithm, digest, signature) in cases {
        assert_eq!(check(&key, algorithm, &digest, &bytes(signature)), Ok(()));
    }
}

#[test]
fn rsa_pss_signature_verifies() {
    let key = rsa_spki(PSS_N, PSS_E);
    let digest = Sha256::digest(bytes(PSS_SHA256_MSG));
    assert_eq!(
        check(
            &key,
            MessageSignatureAlgorithm::RsaPssSha256,
            &digest,
            &bytes(PSS_SHA256_S)
        ),
        Ok(())
    );
}

/// A signature over another digest, or by a key of another size, is a
/// signature the key did not make.
#[test]
fn a_signature_the_key_did_not_make_does_not_verify() {
    let p256 = ec_spki(known::SECP256R1, P256_UX, P256_UY);
    let [(sha256, sample), _, _] = digests(RFC6979_MESSAGE.as_bytes());
    let mut other = sample.clone();
    other.reverse();
    assert_eq!(
        check(&p256, sha256, &other, &bytes(P256_SHA256_RS)),
        Err(DigestCheckError::DoesNotVerify)
    );
    assert_eq!(
        check(&p256, sha256, &sample, &bytes(P384_SHA256_RS)),
        Err(DigestCheckError::DoesNotVerify)
    );
    let rsa = rsa_spki(PKCS1_N, PKCS1_E);
    assert_eq!(
        check(
            &rsa,
            MessageSignatureAlgorithm::RsaPkcs1Sha256,
            &sample,
            &bytes(PKCS1_SHA256_S)
        ),
        Err(DigestCheckError::DoesNotVerify)
    );
    assert_eq!(
        check(
            &rsa,
            MessageSignatureAlgorithm::RsaPkcs1Sha256,
            &Sha256::digest(bytes(PKCS1_SHA256_MSG)),
            &bytes(PSS_SHA256_S)
        ),
        Err(DigestCheckError::DoesNotVerify)
    );
}

/// A key of another kind than the request, or a digest of another
/// length than its hash, is the check's refusal, not a signature that
/// fails to verify.
#[test]
fn a_check_that_cannot_run_is_refused() {
    let p256 = ec_spki(known::SECP256R1, P256_UX, P256_UY);
    let rsa = rsa_spki(PKCS1_N, PKCS1_E);
    let [(sha256, sample), (sha384, _), _] = digests(RFC6979_MESSAGE.as_bytes());
    assert_eq!(
        check(&p256, sha384, &sample, &bytes(P256_SHA256_RS)),
        Err(DigestCheckError::Refused)
    );
    assert_eq!(
        check(&rsa, sha256, &sample, &bytes(P256_SHA256_RS)),
        Err(DigestCheckError::Refused)
    );
    assert_eq!(
        check(
            &p256,
            MessageSignatureAlgorithm::RsaPkcs1Sha256,
            &sample,
            &bytes(PKCS1_SHA256_S)
        ),
        Err(DigestCheckError::Refused)
    );
}
