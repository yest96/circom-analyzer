pragma circom 2.0.0;

template Circuit(){
	signal input in1;
	signal int;
	signal output out1;
	signal input in2;
	signal output out2;

	out1 <-- in1 + in2;
	out2 <== in1 * in2;
	int <== in2 - in1 + 1;
}

component main = Circuit();
