include "./poseidon_constants.circom";

template Circuit() {
    signal input foo;
    signal input bar;
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== foo;
    hasher.inputs[1] <== bar;
    out <== hasher.out;
}

component main = Circuit();
