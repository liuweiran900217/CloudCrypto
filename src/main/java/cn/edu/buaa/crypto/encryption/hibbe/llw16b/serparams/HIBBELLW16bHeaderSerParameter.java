package cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aHeaderSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE header parameter.
 */
public class HIBBELLW16bHeaderSerParameter extends HIBBELLW16aHeaderSerParameter {
    private final CipherParameters signPublicKey;
    private final byte[] signature;

    public HIBBELLW16bHeaderSerParameter(PairingParameters pairingParameters, CipherParameters signPublicKey,
                                         byte[] signature, Element C0, Element C1) {
        super(pairingParameters, C0, C1);
        this.signPublicKey = signPublicKey;
        this.signature = signature;
    }

    public byte[] getSignature() { return this.signature; }

    public CipherParameters getSignPublicKey() { return this.signPublicKey; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16bHeaderSerParameter) {
            HIBBELLW16bHeaderSerParameter that = (HIBBELLW16bHeaderSerParameter) anObject;
            //Compare signature
            if (!Arrays.equals(this.signature, that.signature)) {
                return false;
            }
            //Compare signPublicKey
            return this.signPublicKey.equals(that.signPublicKey) && super.equals(anObject);
        }
        return false;
    }
}