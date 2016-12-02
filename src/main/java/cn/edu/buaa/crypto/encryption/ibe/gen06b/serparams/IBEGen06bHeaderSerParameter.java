package cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams;

import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aHeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CCA2-secure IBE header parameter.
 */
public class IBEGen06bHeaderSerParameter extends IBEGen06aHeaderSerParameter {
    private transient Element y;
    private final byte[] byteArrayY;

    public IBEGen06bHeaderSerParameter(PairingParameters pairingParameters, Element u, Element v, Element y) {
        super(pairingParameters, u, v);
        this.y = y.getImmutable();
        this.byteArrayY = this.y.toBytes();
    }

    public Element getY() { return this.y.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBEGen06bHeaderSerParameter) {
            IBEGen06bHeaderSerParameter that = (IBEGen06bHeaderSerParameter)anObject;
            //Compare y
            if (!PairingUtils.isEqualElement(this.y, that.y)){
                return false;
            }
            if (!Arrays.equals(this.byteArrayY, that.byteArrayY)) {
                return false;
            }
            //Compare supers
            return super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.y = pairing.getGT().newElementFromBytes(this.byteArrayY).getImmutable();
    }
}
