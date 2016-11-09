package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Ciphertext parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05CipherSerParameter extends PairingCipherSerParameter {
    private final int length;
    private final Element B;
    private final Element C;

    public HIBEBBG05CipherSerParameter(PairingParameters pairingParameters, int length, Element B, Element C) {
        super(pairingParameters);
        this.length = length;
        this.B = B.getImmutable();
        this.C = C.getImmutable();
    }

    public int getLength() { return this.length; }

    public Element getB() { return this.B.duplicate(); }

    public Element getC() { return this.C.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBBG05CipherSerParameter) {
            HIBEBBG05CipherSerParameter that = (HIBEBBG05CipherSerParameter)anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            }
            //Compare B
            if (!PairingUtils.isEqualElement(this.B, that.getB())){
                return false;
            }
            //Compare C
            if (!PairingUtils.isEqualElement(this.C, that.getC())){
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
