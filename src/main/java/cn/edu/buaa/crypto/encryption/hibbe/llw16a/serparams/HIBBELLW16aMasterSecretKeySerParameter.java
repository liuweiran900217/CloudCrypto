package cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE master secret key parameter.
 */
public class HIBBELLW16aMasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element g2Alpha;
    private final byte[] byteArrayG2Alpha;

    public HIBBELLW16aMasterSecretKeySerParameter(PairingParameters pairingParameters, Element g2Alpha) {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
        this.byteArrayG2Alpha = this.g2Alpha.toBytes();
    }

    public Element getG2Alpha(){
        return this.g2Alpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16aMasterSecretKeySerParameter) {
            HIBBELLW16aMasterSecretKeySerParameter that = (HIBBELLW16aMasterSecretKeySerParameter)anObject;
            //Compare g2Alpha
            if (!(PairingUtils.isEqualElement(this.g2Alpha, that.getG2Alpha()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2Alpha, that.byteArrayG2Alpha)) {
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
        this.g2Alpha = pairing.getG1().newElementFromBytes(this.byteArrayG2Alpha);
    }
}