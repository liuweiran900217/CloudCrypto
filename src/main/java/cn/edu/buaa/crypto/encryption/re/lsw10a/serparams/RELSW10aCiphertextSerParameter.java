package cn.edu.buaa.crypto.encryption.re.lsw10a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters reovcation encryption ciphertext parameters.
 */
public class RELSW10aCiphertextSerParameter extends RELSW10aHeaderSerParameter {
    private transient Element C;
    private final byte[] byteArrayC;

    public RELSW10aCiphertextSerParameter(PairingParameters pairingParameters, Element C, Element C0, Map<String, Element> C1s, Map<String, Element> C2s) {
        super(pairingParameters, C0, C1s, C2s);

        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();
    }

    public Element getC() { return this.C.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10aCiphertextSerParameter) {
            RELSW10aCiphertextSerParameter that = (RELSW10aCiphertextSerParameter) anObject;
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
