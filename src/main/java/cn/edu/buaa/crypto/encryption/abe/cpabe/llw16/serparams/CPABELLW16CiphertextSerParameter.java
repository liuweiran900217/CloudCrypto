package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-CP-ABE ciphertext parameter.
 */
public class CPABELLW16CiphertextSerParameter extends CPABELLW16HeaderSerParameter {
    private transient Element C;
    private final byte[] byteArrayC;

    public CPABELLW16CiphertextSerParameter(
            PairingParameters pairingParameters, byte[] chameleonHash, byte[] r,
            AsymmetricKeySerParameter chameleonHashPublicKey,
            Element C01, Element C02, Element C03,
            Element C, Element C0, Map<String, Element> C1s, Map<String, Element> C2s,
            Map<String, Element> C3s, Map<String, Element> C4s, Map<String, Element> C5s) {
        super(pairingParameters, chameleonHash, r, chameleonHashPublicKey, C01, C02, C03, C0, C1s, C2s, C3s, C4s, C5s);
        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();
    }

    public Element getC() {
        return this.C.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABELLW16CiphertextSerParameter) {
            CPABELLW16CiphertextSerParameter that = (CPABELLW16CiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.C, that.C)
                    && Arrays.equals(this.byteArrayC, that.byteArrayC)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C = pairing.getGT().newElementFromBytes(this.byteArrayC).getImmutable();
    }
}
