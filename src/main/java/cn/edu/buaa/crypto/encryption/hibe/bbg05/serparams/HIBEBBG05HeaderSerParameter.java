package cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE header / session key pair parameter.
 */
public class HIBEBBG05HeaderSerParameter extends PairingCipherSerParameter {
    private transient Element B;
    private final byte[] byteArrayB;

    private transient Element C;
    private final byte[] byteArrayC;

    public HIBEBBG05HeaderSerParameter(PairingParameters pairingParameters, Element B, Element C) {
        super(pairingParameters);

        this.B = B.getImmutable();
        this.byteArrayB = this.B.toBytes();

        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();
    }

    public Element getB() { return this.B.duplicate(); }

    public Element getC() { return this.C.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBBG05HeaderSerParameter) {
            HIBEBBG05HeaderSerParameter that = (HIBEBBG05HeaderSerParameter)anObject;
            //Compare B
            if (!PairingUtils.isEqualElement(this.B, that.getB())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayB, that.byteArrayB)) {
                return false;
            }
            //Compare C
            if (!PairingUtils.isEqualElement(this.C, that.getC())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayC, that.byteArrayC)) {
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
        this.B = pairing.getG1().newElementFromBytes(this.byteArrayB).getImmutable();
        this.C = pairing.getG1().newElementFromBytes(this.byteArrayC).getImmutable();
    }
}
