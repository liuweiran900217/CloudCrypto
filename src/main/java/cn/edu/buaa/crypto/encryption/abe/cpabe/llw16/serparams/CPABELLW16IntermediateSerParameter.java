package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 intermediate ciphertext parameter.
 */
public class CPABELLW16IntermediateSerParameter extends CPABEHW14IntermediateSerParameter {
    private final byte[] chameleonHash;
    private final byte[] r;

    private final AsymmetricKeySerParameter chameleonHashPublicKey;
    private final AsymmetricKeySerParameter chameleonHashSecretKey;

    private transient Element C01;
    private final byte[] byteArrayC01;

    private transient Element C02;
    private final byte[] byteArrayC02;

    private transient Element C03;
    private final byte[] byteArrayC03;


    public CPABELLW16IntermediateSerParameter(
            PairingParameters parameters, int n,
            byte[] chameleonHash, byte[] r,
            AsymmetricKeySerParameter chameleonHashPublicKey, AsymmetricKeySerParameter chameleonHashSecretKey,
            Element C01, Element C02, Element C03,
            Element sessionKey, Element s, Element C0,
            Element[] lambdas, Element[] ts, Element[] xs, Element[] C1s, Element[] C2s, Element[] C3s) {
        super(parameters, n, sessionKey, s, C0, lambdas, ts, xs, C1s, C2s, C3s);
        this.chameleonHash = chameleonHash;
        this.r = r;
        this.chameleonHashPublicKey = chameleonHashPublicKey;
        this.chameleonHashSecretKey = chameleonHashSecretKey;

        this.C01 = C01.getImmutable();
        this.byteArrayC01 = this.C01.toBytes();

        this.C02 = C02.getImmutable();
        this.byteArrayC02 = this.C02.toBytes();

        this.C03 = C03.getImmutable();
        this.byteArrayC03 = this.C03.toBytes();
    }

    public byte[] getChameleonHash() {
        return this.chameleonHash;
    }

    public byte[] getR() {
        return this.r;
    }

    public AsymmetricKeySerParameter getChameleonHashPublicKey() {
        return this.chameleonHashPublicKey;
    }

    public AsymmetricKeySerParameter getChameleonHashSecretKey() {
        return this.chameleonHashSecretKey;
    }

    public Element getC01() {
        return this.C01.duplicate();
    }

    public Element getC02() {
        return this.C02.duplicate();
    }

    public Element getC03() {
        return this.C03.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABELLW16IntermediateSerParameter) {
            CPABELLW16IntermediateSerParameter that = (CPABELLW16IntermediateSerParameter) anObject;
            if (!PairingUtils.isEqualElement(this.C01, that.C01)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC01, that.byteArrayC01)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C02, that.C02)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC02, that.byteArrayC02)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C03, that.C03)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC03, that.byteArrayC03)) {
                return false;
            }
            //Compare chameleon hash key
            if (!(this.chameleonHashSecretKey.equals(that.chameleonHashSecretKey))) {
                return false;
            }
            if (!(this.chameleonHashPublicKey.equals(that.chameleonHashPublicKey))) {
                return false;
            }
            //Compare chameleon hash
            return Arrays.equals(this.r, that.r)
                    && Arrays.equals(this.chameleonHash, that.chameleonHash)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C01 = pairing.getG1().newElementFromBytes(this.byteArrayC01).getImmutable();
        this.C02 = pairing.getG1().newElementFromBytes(this.byteArrayC02).getImmutable();
        this.C03 = pairing.getG1().newElementFromBytes(this.byteArrayC03).getImmutable();
    }
}
