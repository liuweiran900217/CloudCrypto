package cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams;

import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CCA2-secure IBE public key parameter.
 */
public class IBEGen06bPublicKeySerParameter extends IBEGen06aPublicKeySerParameter {
    private transient Element h2;
    private final byte[] byteArrayH2;

    private transient Element h3;
    private final byte[] byteArrayH3;

    public IBEGen06bPublicKeySerParameter(PairingParameters pairingParameters, Element g, Element g1, Element h, Element h2, Element h3) {
        super(pairingParameters, g, g1, h);
        this.h2 = h2.getImmutable();
        this.byteArrayH2 = this.h2.toBytes();

        this.h3 = h3.getImmutable();
        this.byteArrayH3 = this.h3.toBytes();
    }

    public Element getH2() { return this.h2.duplicate(); }

    public Element getH3() { return this.h3.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof IBEGen06bPublicKeySerParameter) {
            IBEGen06bPublicKeySerParameter that = (IBEGen06bPublicKeySerParameter) anOjbect;
            //Compare h2
            if (!PairingUtils.isEqualElement(this.h2, that.h2)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH2, that.byteArrayH2)) {
                return false;
            }
            //Compare h3
            return PairingUtils.isEqualElement(this.h3, that.h3)
                    && Arrays.equals(this.byteArrayH3, that.byteArrayH3)
                    && super.equals(anOjbect);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.h2 = pairing.getG1().newElementFromBytes(this.byteArrayH2).getImmutable();
        this.h3 = pairing.getG1().newElementFromBytes(this.byteArrayH3).getImmutable();
    }
}
