package cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE public key parameter.
 */
public class HIBBELLW16bPublicKeySerParameter extends HIBBELLW16aPublicKeySerParameter {
    private transient Element uv;
    private final byte[] byteArrayUv;

    public HIBBELLW16bPublicKeySerParameter(PairingParameters parameters,
                                            Element g, Element g1, Element g2, Element g3, Element[] us, Element uv) {
        super(parameters, g, g1, g2, g3, us);
        this.uv = uv.getImmutable();
        this.byteArrayUv = this.uv.toBytes();
    }

    public Element getUv() { return this.uv.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16bPublicKeySerParameter) {
            HIBBELLW16bPublicKeySerParameter that = (HIBBELLW16bPublicKeySerParameter) anObject;
            //Compare uv
            return PairingUtils.isEqualElement(this.uv, that.getUv())
                    && Arrays.equals(this.byteArrayUv, that.byteArrayUv)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.uv = pairing.getG1().newElementFromBytes(this.byteArrayUv).getImmutable();
    }
}
