pragma circom 2.0.0;

template test (N){
   //Declaration of signals.
   signal input in1;
   signal input in[N];
   signal input in2;
   signal input inc[N+1];
   signal output out;

   out <== in1 + in2; 
}
component main = test(5);