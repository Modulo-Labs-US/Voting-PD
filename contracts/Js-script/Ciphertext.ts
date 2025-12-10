

import { babyjub } from "circomlibjs";
import { utils } from "ffjavascript";

/**
 * Encode a scalar as a Babyjub point using m * G
 */
function encodeMessageAsPoint(m: bigint) {
    const G = babyjub.Generator;
    return babyjub.mulPointEscalar(G, m);
}

/**
 * ElGamal encryption over BabyJub
 * pk: [x, y]
 * msgScalar: bigint (your token amount tpi)
 */
export function elgamalEncrypt(
    pk: [bigint, bigint],
    msgScalar: bigint,
    r?: bigint
) {
    const F = babyjub.F;

    // generator
    const G = babyjub.Generator;

    // random r if not provided
    if (!r) {
        r = utils.leBuff2int(utils.randomBytes(32)) % babyjub.SubOrder;
    }

    // message point M = msg * G
    const M = encodeMessageAsPoint(msgScalar);

    // C1 = rG
    const C1 = babyjub.mulPointEscalar(G, r);

    // r*pk
    const rpk = babyjub.mulPointEscalar(pk, r);

    // C2 = M + rpk
    const C2 = babyjub.addPoint(M, rpk);

    return {
        C1x: F.toObject(C1[0]),
        C1y: F.toObject(C1[1]),
        C2x: F.toObject(C2[0]),
        C2y: F.toObject(C2[1]),
        r
    };
}

// Example keys
const sk = "";
const pk = babyjub.mulPointEscalar(babyjub.Generator, sk);

// token voting power
const tpi = 50n;

// encrypt
const ct = elgamalEncrypt(pk as any, tpi);

console.log("Ciphertext:", ct);
