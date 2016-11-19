package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Bethencourt-Sahai-Wtaers large-universe CP-ABE master secret key parameter.
 */
public class CPABEBSW07MasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element gAlpha;
    private final byte[] byteArrayGAlpha;

    private transient Element beta;
    private final byte[] byteArrayBeta;

    public CPABEBSW07MasterSecretKeySerParameter(PairingParameters pairingParameters, Element gAlpha, Element beta) {
        super(true, pairingParameters);
        this.gAlpha = gAlpha.getImmutable();
        this.byteArrayGAlpha = this.gAlpha.toBytes();

        this.beta = beta.getImmutable();
        this.byteArrayBeta = this.beta.toBytes();
    }

    public Element getGAlpha() { return this.gAlpha.duplicate(); }

    public Element getBeta() { return this.beta.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEBSW07MasterSecretKeySerParameter) {
            CPABEBSW07MasterSecretKeySerParameter that = (CPABEBSW07MasterSecretKeySerParameter)anObject;
            //compare gAlpha
            if (!(PairingUtils.isEqualElement(this.gAlpha, that.gAlpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGAlpha, that.byteArrayGAlpha)) {
                return false;
            }
            //compare beta
            if (!(PairingUtils.isEqualElement(this.beta, that.beta))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayBeta, that.byteArrayBeta)) {
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
        this.beta = pairing.getZr().newElementFromBytes(this.byteArrayBeta).getImmutable();
    }
}
