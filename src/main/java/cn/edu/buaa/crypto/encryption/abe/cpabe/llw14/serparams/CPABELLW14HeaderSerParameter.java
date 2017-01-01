package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams;

import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13HeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE header parameter.
 */
public class CPABELLW14HeaderSerParameter extends CPABERW13HeaderSerParameter {
    private final byte[] chameleonHash;
    private final byte[] r;

    private transient Element C01;
    private final byte[] byteArrayC01;

    private transient Element C02;
    private final byte[] byteArrayC02;

    private transient Element C03;
    private final byte[] byteArrayC03;

    public CPABELLW14HeaderSerParameter(
            PairingParameters pairingParameters, byte[] chameleonHash, byte[] r, Element C01, Element C02, Element C03,
            Element C0, Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s) {
        super(pairingParameters, C0, C1s, C2s, C3s);
        this.chameleonHash = chameleonHash;
        this.r = r;

        this.C01 = C01.getImmutable();
        this.byteArrayC01 = this.C01.toBytes();

        this.C02 = C02.getImmutable();
        this.byteArrayC02 = this.C02.toBytes();

        this.C03 = C03.getImmutable();
        this.byteArrayC03 = this.C03.toBytes();
    }

    public byte[] getChameleonHash() { return this.chameleonHash; }

    public byte[] getR() {
        return this.r;
    }

    public Element getC01() { return this.C01.duplicate(); }

    public Element getC02() { return this.C02.duplicate(); }

    public Element getC03() { return this.C03.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABELLW14HeaderSerParameter) {
            CPABELLW14HeaderSerParameter that = (CPABELLW14HeaderSerParameter) anObject;
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
