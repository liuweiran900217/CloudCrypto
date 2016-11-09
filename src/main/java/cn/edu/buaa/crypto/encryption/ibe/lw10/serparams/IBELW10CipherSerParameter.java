package cn.edu.buaa.crypto.encryption.ibe.lw10.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10CipherSerParameter extends PairingCipherSerParameter {

    private transient Element C1;
    private transient Element C2;
    private final byte[] byteArrayC1;
    private final byte[] byteArrayC2;

    public IBELW10CipherSerParameter(PairingParameters pairingParameters, Element C1, Element C2) {
        super(pairingParameters);
        this.C1 = C1.getImmutable();
        this.C2 = C2.getImmutable();
        this.byteArrayC1 = this.C1.toBytes();
        this.byteArrayC2 = this.C2.toBytes();
    }

    public Element getC1() { return this.C1.duplicate(); }

    public Element getC2() { return this.C2.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBELW10CipherSerParameter) {
            IBELW10CipherSerParameter that = (IBELW10CipherSerParameter)anObject;
            //Compare C1
            if (!PairingUtils.isEqualElement(this.C1, that.getC1())){
                return false;
            }
            //Compare C2
            if (!PairingUtils.isEqualElement(this.C2, that.getC2())){
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
        this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1);
        this.C2 = pairing.getG1().newElementFromBytes(this.byteArrayC2);
    }
}
