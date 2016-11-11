package cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE ciphertext parameter.
 */
public class HIBBELLW16bCipherSerParameter extends PairingCipherSerParameter {
    private final CipherParameters signPublicKey;
    private final byte[] signature;

    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element C1;
    private final byte[] byteArrayC1;

    public HIBBELLW16bCipherSerParameter(PairingParameters pairingParameters, CipherParameters signPublicKey, byte[] signature, Element C0, Element C1) {
        super(pairingParameters);
        this.signPublicKey = signPublicKey;
        this.signature = signature;

        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1 = C1.getImmutable();
        this.byteArrayC1 = this.C1.toBytes();
    }

    public Element getC0() {
        return this.C0.duplicate();
    }

    public Element getC1() {
        return this.C1.duplicate();
    }

    public byte[] getSignature() { return this.signature; }

    public CipherParameters getSignPublicKey() { return this.signPublicKey; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16bCipherSerParameter) {
            HIBBELLW16bCipherSerParameter that = (HIBBELLW16bCipherSerParameter) anObject;
            //Compare signature
            if (!Arrays.equals(this.signature, that.signature)) {
                return false;
            }
            //Compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.getC0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //Compare C1
            if (!PairingUtils.isEqualElement(this.C1, that.getC1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC1, that.byteArrayC1)) {
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
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0);
        this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1);
    }
}