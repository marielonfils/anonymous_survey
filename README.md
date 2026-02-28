# Anonymous Survey Scheme - Rust Implementation

A cryptographic implementation of an anonymous survey protocol in Rust, based on the [Anonize](https://eprint.iacr.org/2015/681) framework with simpler assumptions and improved efficiency. This implementation provides privacy-preserving surveys where users can submit runlinkable esponses anonymously while  preventing duplicate submissions.
We also provide an implementation of Anonize for comparison.

## Anonymous survey scheme

A survey scheme involves three types of entities: a single registration authority (RA), survey authorities (SA), and users. The RA is responsible for maintaining a list of registered users. 
Any user wanting to organise a survey can assume the role of the SA. Each user is identified by their public $id$.

First, the user registers to the RA and receives a credential. 
Second, the SA produce a list of survey credentials for the users that are authorized to take part in the survey the SA is creating.
Then, the user creates a submission containing:
- the answer to the survey
- proofs that he is a registered and authorized user
- a token that is unlinkable to the user and which unique for a given survey and a given user. 

If the submission is valid, the SA accepts the submission and replaces any previous submission with the same token


## 🚀 Getting Started

### Prerequisites

- Rust 1.70 or later (edition 2024)
- Cargo

### Installation

1. Clone the repository 

2. Build the project:
```bash
cargo build --release
```

## 🏃 Usage

### Running the Protocols

#### Run the proposed AS (Anonymous Survey) protocol:
```bash
cargo run AS
```

#### Run the Anonize protocol for comparison:
```bash
cargo run AN
```

### Output Format

The program outputs timing measurements in ms:
```
user_type,run_id,RA_setup_time,SA_setup_time,User_setup_time,CRS_generation_time,UR1_time,UR2_time,UR3_time,SR_time,Authorised_time,Submission_time,SubmissionCheck_time,User_time,RA_time,SA_time,Total_time
AS,1,21,212,93,11,4,12,17,1,17,71,184,93,21,212,339
```

Where:
- `RA_setup_time`: Registration Authority key generation
- `SA_setup_time`: Survey Authority key generation  
- `User_setup_time`: User initialization
- `CRS_generation_time`: Common Reference String generation
- `UR1_time`, `UR3_time`: User registration phases for user
- `UR2_time` : User registration time for RA
- `SR_time`: Survey registration
- `Authorised_time`: Authorization check
- `Submission_time`: Survey submission generation
- `SubmissionCheck_time`: Submission verification

### Running Benchmarks

Execute the benchmark suite:
```bash
cargo bench
```

Benchmark results are saved in `target/criterion/` and CSV files in the `benches/` directory.

For custom benchmark scripts:
```bash
cd benches/
bash bench.sh
```

## 🔧 Technical Overview

This implementation uses:
- **Curve**: BLS12-381 pairing-friendly elliptic curve
- **Framework**: [arkworks](https://arkworks.rs/) ecosystem for elliptic curve and pairing operations
- **Cryptographic Primitives**:
  - Structure-Preserving Signatures (SPS) : implemented
  - Boneh-Boyen (BB) signatures : implemented
  - Groth-Sahai NIZK proofs : implemented
  - One-Time Signatures (Lamport-Diffie and Pedersen-based): implemented
  - Hash-to-Curve functions : from arkworks

## 🔬 Cryptographic Parameters

- **Security Level**: 128 bits 
- **Fischlin Transform**: λ = 32, B = 4 (4-bit zero prefix for hashes) (configurable in `lib.rs`)
- **Curve**: BLS12-381 with groups G1, G2, GT
- **Hash Function**: SHA-256
- **Domain Separator**: `ANONYMOUS_SURVEY_BLS12381:SHA-256_SSWU_RO_POP_`

## Differences compared to Anonize

We replace:
- the generic NIZK proof system with Groth--Sahai (GS) proofs which significantly reduces the number of pairing computations required from the user,
- partially blind signatures with a structure-preserving signature (SPS) scheme which accommodates efficient GS-based verification,
- the Dodis--Yampolskiy PRF with a hashed Diffie--Hellman PRF, which allows the token to be in $G_1$ instead of $G_T$. 

We further modify the user registration and submission steps to guarantee the security of the scheme under the new primitives.

## 📊 Performance Characteristics

The implementation provides significant improvements over Anonize:
- **Simplified assumptions** only requiring hardness of SXDH
- **Reduced computation time** for submission generation and verification
- **Lower communication costs** for user registration and for submissionthrough compressed serialization

Run benchmarks to see detailed performance metrics on your system.

## 📁 Project Structure

```
code/
├── src/
│   ├── lib.rs                      # Library entry point with constants
│   ├── main.rs                     # Main executable for running protocols
│   ├── registration_authority.rs   # RA implementation
│   ├── survey_authority.rs         # SA implementation  
│   ├── as_user.rs                  # User implementation for proposed protocol
│   ├── an_user.rs                  # User implementation for Anonize
│   └── utils/
│       ├── mod.rs                  # Utilities module
│       ├── utils.rs                # Common data structures and helpers
│       ├── errors.rs               # Error types
│       ├── curve_hasher.rs         # Hash-to-curve functionality
│       ├── gs.rs                   # Groth-Sahai proof system
│       ├── signature/
│       │   ├── mod.rs
│       │   ├── pbbb.rs             # Boneh-Boyen signatures
│       │   └── sps_improved.rs     # Structure-Preserving Signatures
│       └── ots/
│           ├── mod.rs
│           ├── ots.rs              # Generic OTS interface
│           ├── lamport_diffie.rs   # Lamport-Diffie OTS
│           └── (Pedersen-based OTS in ots.rs)
├── benches/
│   ├── my_benchmark.rs             # Criterion benchmarks
│   ├── benches_sep.rs              # Additional benchmarks
│   ├── bench.sh                    # Benchmark execution script
│   └── *.csv                       # Benchmark results
└── Cargo.toml                      # Project dependencies
```
## 🔑 Key Components

### Entities

1. **Registration Authority (RA)** (`registration_authority.rs`)
   - Registers users in the system
   - Verifies user registration proofs
   - Issues credentials via signatures


2. **Survey Authority (SA)** (`survey_authority.rs`)
   - Creates surveys with unique identifiers
   - Publishes lists of survey credentials for authorized participants
   - Verifies submissions and checks tokens

3. **Users** (`as_user.rs`, `an_user.rs`)
   - Register with RA to obtain user credentials
   - Submit anonymous survey responses to SA
   - Generate zero-knowledge proofs of eligibility

### Protocol Flow

1. **System Setup**
   - Initialize pairing groups (BLS12-381)
   - Generate RA and SA signature keys
   - Create Common Reference String (CRS) for Groth-Sahai proofs
   - Initialize users

2. **User Registration** (3 phases)
   - User chooses a secret $sid$, compute $pk=g^{sid}$ and generates proof that pk is well formed
   - RA verifies proof and issues credential signature
   - User stores credential if valid

3. **Survey Registration**
   - SA generates survey identifier $vid$
   - SA creates authorization list of eligible users
   - SA publishes list of signatures on §(vid, pk)$ for authorized participants

4. **Authorization Check**
   - Verify if a user is authorized for a specific survey through the signature in the list published by the SA

5. **Survey Submission**
   - User generates submission with:
     - Survey answer
     - Unlinkable one-time token (prevents duplicate submissions)
     - Proofs of:
       - Valid RA credential possession
       - Valid SA credential possession
       - Correct token formation

6. **Submission Verification**
   - SA verifies all proofs
   - Checks for duplicate tokens
   - Accepts or rejects submission
   * This step can be performed by any entity 

## 🔐 Configuration Options

The implementation supports different proof systems and signature schemes:

### Proof Systems
- `GS`: Custom Groth-Sahai implementation
- `GSLIB`: Groth-Sahai from external library (less efficient)
- `Schnorr`: Schnorr proofs (for user registration only)

### Signature Schemes
- **AS Protocol**: SPS (Structure-Preserving Signatures)
- **Anonize**: BB (Boneh-Boyen signatures)

### One-Time Signature Schemes
- `LD`: Lamport-Diffie OTS
- `P`: Pedersen-based OTS

Configure these in `main.rs`:
```rust
let ur_proof_type = "GS";           // User registration proof type
let submission_proof_type = "GS";   // Submission proof type
let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {});
```







## 🔗 External Resources
- [Anonize description](https://eprint.iacr.org/2015/681)
- [arkworks documentation](https://docs.rs/ark-ec/)
- [BLS12-381 specification](https://link.springer.com/chapter/10.1007/3-540-36413-7_19)
- [Groth-Sahai proofs](https://eprint.iacr.org/2007/155)

## ⚠️ Security Notice

This is a **research prototype** implementation intended for academic evaluation. It has not undergone formal security audits and should not be used in production systems without thorough review and testing.



