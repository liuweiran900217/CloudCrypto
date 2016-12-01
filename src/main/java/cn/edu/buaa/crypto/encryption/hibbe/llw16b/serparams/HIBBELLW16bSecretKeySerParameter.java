package cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aSecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE secret key parameter.
 */
public class HIBBELLW16bSecretKeySerParameter extends HIBBELLW16aSecretKeySerParameter {
    private transient Element bv;
    private final byte[] byteArrayBv;

    public HIBBELLW16bSecretKeySerParameter(PairingParameters pairingParameters, String[] ids, Element[] elementIds,
                                            Element a0, Element a1, Element[] bs, Element bv) {
        super(pairingParameters, ids, elementIds, a0, a1, bs);
        this.bv = bv.getImmutable();
        this.byteArrayBv = this.bv.toBytes();
    }

    public Element getBv() { return this.bv.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof HIBBELLW16bSecretKeySerParameter) {
            HIBBELLW16bSecretKeySerParameter that = (HIBBELLW16bSecretKeySerParameter) anOjbect;
            return PairingUtils.isEqualElement(this.bv, that.getBv())
                    && Arrays.equals(this.byteArrayBv, that.byteArrayBv)
                    && super.equals(anOjbect);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.bv = pairing.getG1().newElementFromBytes(this.byteArrayBv).getImmutable();
    }
}
