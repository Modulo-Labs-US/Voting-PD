
pragma circom 2.1.6;



include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/bitify.circom";        // Num2Bits
include "../node_modules/circomlib/circuits/escalarmulfix.circom"; // EscalarMulFix (fixed-base)
 
// -----------------------------
// Variable-base scalar mul (double-and-add)
// -----------------------------
template ScalarMul(nBits) {
    signal input Px;
    signal input Py;
    signal input scalar; // field element representing integer scalar

    signal output Sx;
    signal output Sy;

    // get scalar bits (little-endian)
    component bits = Num2Bits(nBits);
    bits.in <== scalar;

    // arrays (declare up front — no signal/component declarations inside loop)
    signal baseX[nBits];
    signal baseY[nBits];
    signal accX[nBits+1];
    signal accY[nBits+1];

    // helper arrays for the selector patch
    signal bArr[nBits];        // bArr[i] will hold bits.out[i]
    signal deltaX[nBits];      // deltaX[i] = adds[i].xout - accX[i]
    signal deltaY[nBits];      // deltaY[i] = adds[i].yout - accY[i]

    // component arrays (components must also be declared before/at top of loop)
    component dbls[nBits-1];
    component adds[nBits];

    // init
    baseX[0] <== Px;
    baseY[0] <== Py;

    accX[0] <== 0;
    accY[0] <== 1; // identity on babyjub

    for (var i = 0; i < nBits; i++) {
        // instantiate adder
        adds[i] = BabyAdd();
        adds[i].x1 <== accX[i];
        adds[i].y1 <== accY[i];
        adds[i].x2 <== baseX[i];
        adds[i].y2 <== baseY[i];

        // selector patch (quadratic-safe)
        bArr[i] <== bits.out[i];

        // compute difference delta = addOut - acc (linear)
        deltaX[i] <== adds[i].xout - accX[i];
        deltaY[i] <== adds[i].yout - accY[i];

        // acc_{i+1} = acc + delta * b  (degree <= 2)
        accX[i+1] <== accX[i] + deltaX[i] * bArr[i];
        accY[i+1] <== accY[i] + deltaY[i] * bArr[i];

        if (i < nBits - 1) {
            // base = 2 * base (doubling)
            dbls[i] = BabyAdd();
            dbls[i].x1 <== baseX[i];
            dbls[i].y1 <== baseY[i];
            dbls[i].x2 <== baseX[i];
            dbls[i].y2 <== baseY[i];

            baseX[i+1] <== dbls[i].xout;
            baseY[i+1] <== dbls[i].yout;
        }
    }

    Sx <== accX[nBits];
    Sy <== accY[nBits];
}

// -----------------------------
// ElGamal ciphertext correctness check
// C1 = r*G
// C2 = m*G + r*PK
// -----------------------------
template ElGamalCheck() {
    // public inputs: ciphertext and public key
    signal input   C1x;
    signal input  C1y;
    signal input  C2x;
    signal input  C2y;
    signal input  PKx;
    signal input  PKy;

    // private inputs: scalars r and m (field elements)
    signal input r;
    signal input m;

    // --- Constants: Generator G in twisted edwards (same as in library)
    // var BASE8 = [
    //     5299619240641551281634865583518297030282874472190772894086521144482721001553,
    //     16950150798460657717958625567821834550301663161624707787222815936182638968203
    // ];
 var Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
  var Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

// var G = [
//     5299619240641551281634865583518297030282874472190772894086521144482721001553,
//     16950150798460657717958625567821834550301663161624707787222815936182638968203
// ];

    // r bits
    component rBits = Num2Bits(253);
    rBits.in <== r;

    // m bits
    component mBits = Num2Bits(253);
    mBits.in <== m;

    // --- r * G (fixed base)
//     component rG = EscalarMulFix(253, G);
// for (var i = 0; i < 253; i++) {
//     rG.e[i] <== rBits.out[i];
// }
// signal Rx <== rG.out[0];
// signal Ry <== rG.out[1];

    // -----------------------------
    // r * G  (use EscalarMulFix with r bits)
    // EscalarMulFix expects an array of bits; we derive them with Num2Bits
    // -----------------------------
    // component rBits = Num2Bits(253);
    // rBits.in <== r;

component rG = EscalarMulFix(253, [Gx,Gy]);
for (var i = 0; i < 253; i++) {
    rG.e[i] <== rBits.out[i];
}
signal Rx <== rG.out[0];
signal Ry <== rG.out[1];


    // enforce C1 == rG
    C1x === Rx;
    C1y === Ry;

// --- m * G (fixed base)
   component mG = EscalarMulFix(253, [Gx,Gy]);
for (var i = 0; i < 253; i++) {
    mG.e[i] <== mBits.out[i];
}
signal Mx <== mG.out[0];
signal My <== mG.out[1];


    // -----------------------------
    // r * PK  (variable-base scalar mul)
    // -----------------------------
    component rPK = ScalarMul(253);
    rPK.Px <== PKx;
    rPK.Py <== PKy;
    rPK.scalar <== r;
    signal rPKx <== rPK.Sx;
    signal rPKy <== rPK.Sy;

    // -----------------------------
    // V = M + rPK
    // -----------------------------
    component add = BabyAdd();
    add.x1 <== Mx;
    add.y1 <== My;
    add.x2 <== rPKx;
    add.y2 <== rPKy;

    signal Vx <== add.xout;
    signal Vy <== add.yout;

    // enforce C2 == V
    C2x === Vx;
    C2y === Vy;
}

component main{ public [C1x,C2x,C1y,C2y,PKx,PKy]} = ElGamalCheck();
