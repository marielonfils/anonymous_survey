#![allow(warnings)]
use ark_ec::{AffineRepr, PrimeGroup, pairing::Pairing, pairing::PairingOutput,
hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,map_to_curve_hasher::MapToCurve}, };
use ark_ff::{BigInt, Field, PrimeField};
use ark_std::{UniformRand, test_rng, rand::Rng};

use rand::rand_core::le;
use rand::{rng, thread_rng};


use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2, G1Affine, G2Affine, Fr as ScalarField, Fq, g1::Config as G1Config};
use ark_ff::field_hashers::DefaultFieldHasher;
use sha2::{ Sha256};



use groth_sahai::{AbstractCrs, B, CRS as CRSLib};

use anonymous_survey::{DOMAIN}; 
use anonymous_survey::utils::utils::{setup,CRS,generate_crs,CRStype, Group, SignatureSchemeType,OTSignatureSchemeType, User, UserTrait};
use anonymous_survey::survey_authority::{SA,authorized};
use anonymous_survey::registration_authority::{RA};
use anonymous_survey::as_user::{UserAS};
use anonymous_survey::an_user::{UserAN};
use anonymous_survey::utils::signature::pbbb::{BBSignatureScheme};
use anonymous_survey::utils::signature::sps_improved::{SPSImpSignatureScheme};
use anonymous_survey::utils::ots::lamport_diffie::{LDOTSignatureScheme};
use anonymous_survey::utils::ots::ots::{POTSignatureScheme};
use anonymous_survey::utils::gs::CrsG2;

use std::time::Instant;
use std::{env, vec};

use std::mem::size_of_val;
//use size_of::size_of_values;



fn main() {
    let args: Vec<String> = env::args().collect();
    let scheme = &args[1]; //AS for anonymous survey or AN for anonize
    let exp_type = &args[2];
    let run_id = &args[3];

    let mut rng = test_rng();
    let signature_scheme_type:SignatureSchemeType; //SPSImp for AS, BB for AN
    let crs_ur : CRS<Bls12_381>;
    let crs_type:CRStype;
    let group1:Group;
    let group2:Group;
    
    let mut schnorr= false;
    let ur_proof_type = "GS" ;//"GS" for GS implemented, "GSLIB" for GS from library, "Schnorr" for Schnorr proof in user registration
    let submission_proof_type = "GS"; //"GSLIB", "GS" in submission
    
    let (signature_scheme_type, crs_type, group1, group2) = setup(scheme, ur_proof_type, submission_proof_type, &mut rng);

    //RA generation
    let start_ra = Instant::now();
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    let t_ra = start_ra.elapsed();
    //SA generation
    let start_sa = Instant::now();
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    let t_sa = start_sa.elapsed();
    //CRS generation
    let start_crs = Instant::now();
    //GS library : crs for RA and SA signature possession proofs, crs2 for token validity proof, crs_exp is None
    //GS implemented: crs and crs2 for RA and SA signature possession proofs, crs_exp for token validity proof
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);
    let crs_ur = crs2;
    //ots scheme : LD or P 
    //let ots_scheme = OTSignatureSchemeType::LD(LDOTSignatureScheme {  });
    let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {  });      
    let t_crs = start_crs.elapsed();

    //User
    let start_user = Instant::now();
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);
    let t_u = start_user.elapsed();

    // User registration    
    let start_ur1 = Instant::now();
    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let t_ur1= start_ur1.elapsed();
    let start_ra2 = Instant::now();
    let signature_ra = ra.user_registration_2(&mut rng,&user_ra_comm, &crs_ur).unwrap();
    let t_ur2 = start_ra2.elapsed();
    let sur1 = size_of_val(&user_ra_comm);
    let e2 = G2::generator() * ScalarField::rand(&mut rng);
    let e1 = G1::generator() * ScalarField::rand(&mut rng);
    println!("Random element in G1 size: {}, {}",size_of::<G1Affine>(), size_of_val(&e1));
    println!("Random element in G2 size: {}", size_of_val(&e2));
    eprintln!("pairing output size: {}", size_of_val::<PairingOutput<Bls12_381>>(&Pairing::pairing(e1,e2)));
    println!("zq size: {}", size_of_val(&ScalarField::rand(&mut rng)));
    //println!("User registration 1 communication size: {} {} {}", sur1, size_of_val(&user_ra_comm.proof.gsu_value().commitment.com1), size_of_val(user_ra_comm.id)+size_of_val(user_ra_comm.pk)+size_of_val(&user_ra_comm.proof.gsu_value().commitment.com1)+size_of_val(&user_ra_comm.proof.gsu_value().commitment.com2)+size_of_val(&user_ra_comm.proof.gsu_value().proof.p));
    //let chal = (*user_ra_comm.proof.sc2_value().challenge).len();
    //println!("Chal: {:?}", chal);
    //println!("User registration 1 communication size: {} {} {} {}", sur1,size_of_val(&user_ra_comm.proof.sc2_value().challenge[0]), size_of_val(&user_ra_comm.id)+size_of_val(&user_ra_comm.pk)+size_of_val(&user_ra_comm.proof.sc2_value().commitment[0])*&user_ra_comm.proof.sc2_value().commitment.len()+ size_of_val(&user_ra_comm.proof.sc2_value().challenge[0])*&user_ra_comm.proof.sc2_value().challenge.len()+ size_of_val(&user_ra_comm.proof.sc2_value().response1[0])*&user_ra_comm.proof.sc2_value().response1.len()+ size_of_val(&user_ra_comm.proof.sc2_value().response2[0])*&user_ra_comm.proof.sc2_value().response2.len()+size_of_val(&user_ra_comm.proof.sc2_value().challenge)+size_of_val(&user_ra_comm.proof.sc2_value().response1)+size_of_val(&user_ra_comm.proof.sc2_value().response2),     size_of_val(&user_ra_comm.id)+size_of_val(&user_ra_comm.pk)+size_of_val(&user_ra_comm.proof.sc2_value().commitment[0])*&user_ra_comm.proof.sc2_value().commitment.capacity()+ size_of_val(&user_ra_comm.proof.sc2_value().challenge[0])*&user_ra_comm.proof.sc2_value().challenge.capacity()+ size_of_val(&user_ra_comm.proof.sc2_value().response1[0])*&user_ra_comm.proof.sc2_value().response1.capacity()+ size_of_val(&user_ra_comm.proof.sc2_value().response2[0])*&user_ra_comm.proof.sc2_value().response2.capacity()); 
    //println!("ur2 {} {}", size_of_val(&signature_ra),size_of_val(&signature_ra.sps_imp_value().pi)+size_of_val(&signature_ra.sps_imp_value().rho)+size_of_val(&signature_ra.sps_imp_value().rho_hat)+size_of_val(&signature_ra.sps_imp_value().psi)+size_of_val(&signature_ra.sps_imp_value().tau)+size_of_val(&signature_ra.sps_imp_value().gamma));
    //println!("ur2 {} {}", size_of_val(&signature_ra),size_of_val(&signature_ra.bb_value().s1)+size_of_val(&signature_ra.bb_value().s2)+size_of_val(&signature_ra.bb_value().s3));
    let start_user2 = Instant::now();
    user.user_registration_3(&signature_ra).unwrap();
    let t_ur3 = start_user2.elapsed();

    // Survey registration
    let start_sa2 = Instant::now();
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    user.set_signature_sa(&signature_sa);
    let t_sr = start_sa2.elapsed();
    //let s_sa = size_of_val(&signature_sa.sps_imp_value().pi)+size_of_val(&signature_sa.sps_imp_value().rho)+size_of_val(&signature_sa.sps_imp_value().rho_hat)+size_of_val(&signature_sa.sps_imp_value().psi)+size_of_val(&signature_sa.sps_imp_value().tau)+size_of_val(&signature_sa.sps_imp_value().gamma);
    //println!("Survey registration communication size: {}, {}", size_of_val(&signature_sa), s_sa);
    //println!("sr {}", size_of_val(&signature_sa.bb_value().s1)+size_of_val(&signature_sa.bb_value().s2)+size_of_val(&signature_sa.bb_value().s3));
    // Authorised
    let start_auth = Instant::now();
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    let t_auth = start_auth.elapsed();

    // Submission
    let start_sub = Instant::now();
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    //let submission_size = size_of_val(&submission.as_value().pk_commitment.gs_value().com1)+size_of_val(&submission.as_value().pk_commitment.gs_value().com2)+size_of_val(&submission.as_value().token)+size_of_val(&submission.as_value().ovk.p_value().vk_1)+size_of_val(&submission.as_value().ovk.p_value().vk_2)+size_of_val(&submission.as_value().ovk.p_value().hk)+size_of_val(&submission.as_value().ots.p_value().s1)+size_of_val(&submission.as_value().ots.p_value().s2)+size_of_val(&submission.as_value().proof.gs_value().0.commitments[0].com1)*14+size_of_val(&submission.as_value().proof.gs_value().0.proofs.p1)+size_of_val(&submission.as_value().proof.gs_value().0.proofs.p2)+size_of_val(&submission.as_value().proof.gs_value().1.commitments.com1)*2+size_of_val(&submission.as_value().proof.gs_value().1.proofs.p1_11)*4+size_of_val(&submission.as_value().proof.gs_value().1.proofs.p2_11)*4+size_of_val(&submission.as_value().proof.gs_value().2.commitments[0].com1)*10+size_of_val(&submission.as_value().proof.gs_value().2.proofs.p1)*2+size_of_val(&submission.as_value().proof.gs_value().3.commitments.com1)*2+size_of_val(&submission.as_value().proof.gs_value().3.proofs.p1_11)*4+size_of_val(&submission.as_value().proof.gs_value().3.proofs.p2_11)*4+size_of_val(&submission.as_value().proof.gs_value().4.commitments[0].com1)*6+size_of_val(&submission.as_value().proof.gs_value().4.proofs.p1)*3;
    let submission_size= size_of_val(&submission.an_value().token)+size_of_val(&submission.an_value().s2)+size_of_val(&submission.an_value().s4)+size_of_val(&submission.an_value().proof.e1[0])*submission.an_value().proof.e1.capacity()+size_of_val(&submission.an_value().proof.e2[0])*submission.an_value().proof.e2.capacity()+size_of_val(&submission.an_value().proof.e3[0])*submission.an_value().proof.e3.capacity()+size_of_val(&submission.an_value().proof.challenge[0])*submission.an_value().proof.challenge.capacity()+size_of_val(&submission.an_value().proof.z1[0])*submission.an_value().proof.z1.capacity()+size_of_val(&submission.an_value().proof.z2[0])*submission.an_value().proof.z2.capacity()+size_of_val(&submission.an_value().proof.z3[0])*submission.an_value().proof.z3.capacity()+size_of_val(&submission.an_value().proof.z4[0])*submission.an_value().proof.z4.capacity();
    println!("Sub size {}", submission_size);
    let t_sub = start_sub.elapsed();
    let start_sub2 = Instant::now();
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();
    let t_sub2 = start_sub2.elapsed();
    println!("Submission communication size: {}", submission_size);

    let t_user = t_u+t_ur1 + t_ur3 + t_sub;
    let t_ra = t_ra + t_ur2;
    let t_sa = t_sa + t_sr + t_auth + t_sub2;
    let t_tot= t_user + t_ra + t_sa + t_crs;
    println!("{}, {}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",exp_type, run_id, t_ra.as_millis(), t_sa.as_millis(), t_user.as_millis(), t_crs.as_millis(), t_ur1.as_millis(), t_ur2.as_millis(), t_ur3.as_millis(), t_sr.as_millis(), t_auth.as_millis(), t_sub.as_millis(), t_sub2.as_millis(), t_user.as_millis(), t_ra.as_millis(), t_sa.as_millis(), t_tot.as_millis());
    
     
    let g1 = G1::generator();
    let g2 = G2::generator();
    let s=ScalarField::from(82);
    let mut res:PairingOutput<Bls12_381> = Pairing::pairing(g1,g2);
    //let res2=Pairing::pairing(g1*s, g2);
    let mut v: Vec<PairingOutput<Bls12_381>> = vec![Pairing::pairing(g1,g2);100];
    let mut rng = test_rng();
    for i in 0..100 {
        let s = ScalarField::rand(&mut rng);
        v[i]=Pairing::pairing(g1*s, g2);
    }
    let start_pm = Instant::now();
    for i in 0..100  {
        res = res+v[i];
    }
    let t_pm = start_pm.elapsed();
    println!("Pairing multiplication time: {:?}", t_pm/100);

    let mut v2 :Vec<ScalarField> = vec![ScalarField::from(0);100];
    for i in 0..100 {
        let s = ScalarField::rand(&mut rng);
        v2[i]=s;
    }
    let mut sum:ScalarField=ScalarField::from(0);
    let start_aq = Instant::now();
    for i in 0..100  {
        sum = sum + v2[i];
    }
    let t_aq = start_aq.elapsed();
    println!("ScalarField addition time: {:?}", t_aq/100);
    let mut prod: ScalarField=ScalarField::from(1);
    let start_mq = Instant::now();
    for i in 0..100  {
        prod = prod * v2[i];
    }
    let t_mq = start_mq.elapsed();
    println!("ScalarField multiplication time: {:?}", t_mq/100);

    let mut v3: Vec<G1> = vec![g1;100];
    for i in 0..100 {
        let s = ScalarField::rand(&mut rng);
        v3[i]=g1*s;
    }
    let start_h = Instant::now();
    for i in 0..100  {
        let g1_mapper = MapToCurveBasedHasher::<
                G1,//G1Projective, //<G1Config>,
                DefaultFieldHasher<Sha256, 256>,
                WBMap<G1Config>,
            >::new(DOMAIN)
            .unwrap();
            let hash = g1_mapper.hash(v3[i].to_string().as_bytes()).unwrap();
    }
    let t_h = start_h.elapsed();
    println!("G1 Hashing time: {:?}", t_h/100);
    
    let g1 = G1::generator();
    let s=ScalarField::from(82);
    let start_e1 = Instant::now();
    let mut res1:G1;
    for i in 0..100  {
        res1 = g1*s;
    }
    let t_e1 = start_e1.elapsed();
    println!("E1 time: {:?}", t_e1/100);

    let g2 = G2::generator();
    let start_e2 = Instant::now();
    let mut res2:G2;
    for i in 0..100  {
        res2 = g2*s;
    }
    let t_e2 = start_e2.elapsed();
    println!("E2 time: {:?}", t_e2/100);

    let mut res:PairingOutput<Bls12_381>= Pairing::pairing(g1,g2);
    let start_p = Instant::now();    
    for i in 0..100  {
        res = Pairing::pairing(g1,g2);
    }
    let t_p = start_p.elapsed();
    println!("Pairing time: {:?}", t_p/100);

    let start_p = Instant::now();
    for i in 0..100  {
        res = res*s;
    }
    let t_p = start_p.elapsed();
    println!("Pairing exponentiation time: {:?}", t_p/100);

    let g11=g1*s;
    let start_m1 = Instant::now();
    for i in 0..100  {
        res1 = g1+g11;
    }
    let t_m1 = start_m1.elapsed();
    println!("M1 time: {:?}", t_m1/100);

    let g21=g2*s;
    let start_m2 = Instant::now();
    for i in 0..100  {
        res2 = g2+g21;
    }
    let t_m2 = start_m2.elapsed();
    println!("M2 time: {:?}", t_m2/100);

}
