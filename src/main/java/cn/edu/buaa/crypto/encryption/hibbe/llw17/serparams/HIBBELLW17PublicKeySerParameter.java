package cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE public key parameter.
 */
public class HIBBELLW17PublicKeySerParameter extends HIBBELLW14PublicKeySerParameter {
    private transient Element uv;
    private final byte[] byteArrayUv;

    public HIBBELLW17PublicKeySerParameter(PairingParameters parameters, Element g, Element h, Element[] u, Element uv, Element X3, Element eggAlpha) {
        super(parameters, g, h, u, X3, eggAlpha);

        this.uv = uv.getImmutable();
        this.byteArrayUv = this.uv.toBytes();
    }

    public Element getUv() { return this.uv.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW17PublicKeySerParameter) {
            HIBBELLW17PublicKeySerParameter that = (HIBBELLW17PublicKeySerParameter) anObject;
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
