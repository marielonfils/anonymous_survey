#!/usr/bin/env bash
RUNS=50
OUT="bench9.csv"

# CSV header
echo "user_type,run_id,RA_setup,SA_setup,U_setup,CRS,UR1,UR2,UR3,SR,Auth,Sub,Sub2,User,RA,SA,Tot" > "$OUT"

cargo build --release

USER="AN"
for ((i=1; i<=RUNS; i++)); do
    cargo run --release AN "$USER" "$i" >> "$OUT"
done
USER="AS"
for ((i=1; i<=RUNS; i++)); do
    cargo run --release AS "$USER" "$i" >> "$OUT"
done
