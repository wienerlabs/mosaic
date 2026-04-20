pragma circom 2.0.0;

// Proves knowledge of (a, b) such that a * b == c, where c is public.
// Matches the mul-circuit fixture used by the Groth16 path for consistency.
template MulCheck() {
    signal input a;  // private witness
    signal input b;  // private witness
    signal input c;  // public input
    a * b === c;
}

component main {public [c]} = MulCheck();
