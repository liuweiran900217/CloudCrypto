package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters reovcation encryption ciphertext parameters.
 */
public class RELSW10ACipherSerParameter extends PairingCipherSerParameter {
    private final int length;
    private final Element C0;
    private final Element[] C1s, C2s;

    public RELSW10ACipherSerParameter(PairingParameters pairingParameters,
                                      int length, Element C0, Element[] C1s, Element[] C2s) {
        super(pairingParameters);
        this.length = length;
        this.C0 = C0.getImmutable();
        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.C2s = ElementUtils.cloneImmutable(C2s);
    }

    public int getLength() { return this.length; }

    public Element getC0() { return this.C0.duplicate(); }

    public Element getC1sAt(int index) { return this.C1s[index].duplicate(); }

    public Element[] getC1s() { return this.C1s; }

    public Element getC2sAt(int index) { return this.C2s[index].duplicate(); }

    public Element[] getC2s() { return this.C2s; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10ACipherSerParameter) {
            RELSW10ACipherSerParameter that = (RELSW10ACipherSerParameter) anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            }
            //Compre C0
            if (!PairingUtils.isEqualElement(this.C0, that.getC0())) {
                return false;
            }
            //Compare C1s
            if (!PairingUtils.isEqualElementArray(this.C1s, that.getC1s())) {
                return false;
            }
            //Compare C2s
            if (!PairingUtils.isEqualElementArray(this.C2s, that.getC2s())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
