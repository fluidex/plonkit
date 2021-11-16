// inspired by https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649
// the circuit proves you know some 'x' that satisfies 'x**3 + x + 5 == 35' without revealing what is x
template Circuit() {
    signal input y;
    signal input x;

    signal tmp;
    tmp <== x * x;
    y === tmp * x + x + 5;
}

component main = Circuit();
