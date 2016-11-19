package cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE master secret key serializable parameter.
 */
public class HIBBELLW14MasterSecretKeySerParameter extends PairingKeySerParameter {

    private transient Element gAlpha;
    private final byte[] byteArrayGAlpha;

    public HIBBELLW14MasterSecretKeySerParameter(PairingParameters pairingParameters, Element gAlpha) {
        super(true, pairingParameters);
        this.gAlpha = gAlpha.getImmutable();
        this.byteArrayGAlpha = this.gAlpha.toBytes();
    }

    public Element getGAlpha(){
        return this.gAlpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW14MasterSecretKeySerParameter) {
            HIBBELLW14MasterSecretKeySerParameter that = (HIBBELLW14MasterSecretKeySerParameter)anObject;
            //Compare gAlpha
            if (!(PairingUtils.isEqualElement(this.gAlpha, that.getGAlpha()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGAlpha, that.byteArrayGAlpha)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.gAlpha = pairing.getG1().newElementFromBytes(this.byteArrayGAlpha).getImmutable();
    }
}
