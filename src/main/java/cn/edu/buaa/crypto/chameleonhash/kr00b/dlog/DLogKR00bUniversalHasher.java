package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bPublicKeyParameters;
import org.bouncycastle.crypto.Digest;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/11/7.
 *
 *
 */
public class DLogKR00bUniversalHasher extends DLogKR00bHasher {
    private Digest digest;

    public DLogKR00bUniversalHasher(Digest digest) {
        this.digest = digest;
    }

    public BigInteger[] computeHash(byte[] message) {
        BigInteger[] hashResult = super.computeHash(message);
        return compute_universal_hash(hashResult);
    }

    public BigInteger[] computeHash(byte[] message, BigInteger r) {
        BigInteger[] hashResult = super.computeHash(message, r);
        return compute_universal_hash(hashResult);
    }

    private BigInteger[] compute_universal_hash(BigInteger[] hashResult) {
        DLogKR00bPublicKeyParameters publicKeyParameters = (DLogKR00bPublicKeyParameters) key;

        byte[] byteArrayP = publicKeyParameters.getParameters().getP().toByteArray();
        byte[] byteArrayQ = publicKeyParameters.getParameters().getQ().toByteArray();
        byte[] byteArrayG = publicKeyParameters.getParameters().getG().toByteArray();
        byte[] byteArrayY = publicKeyParameters.getY().toByteArray();
        byte[] byteArrayCh = hashResult[0].toByteArray();
        digest.reset();
        digest.update(byteArrayP, 0, byteArrayP.length);
        digest.update(byteArrayQ, 0, byteArrayQ.length);
        digest.update(byteArrayG, 0, byteArrayG.length);
        digest.update(byteArrayY, 0, byteArrayY.length);
        digest.update(byteArrayCh, 0, byteArrayCh.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return new BigInteger[] {
                new BigInteger(hash),
                hashResult[1],
                hashResult[2],
        };
    }
}
