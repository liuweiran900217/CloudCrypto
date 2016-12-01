package cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE header parameter.
 */
public class IBEGen06aHeaderSerParameter extends PairingCipherSerParameter {
    private transient Element u;
    private final byte[] byteArrayU;

    private transient Element v;
    private final byte[] byteArrayV;

    public IBEGen06aHeaderSerParameter(PairingParameters pairingParameters, Element u, Element v) {
        super(pairingParameters);
        this.u = u.getImmutable();
        this.byteArrayU = this.u.toBytes();

        this.v = v.getImmutable();
        this.byteArrayV = this.v.toBytes();
    }

    public Element getU() { return this.u.duplicate(); }

    public Element getV() { return this.v.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBEGen06aHeaderSerParameter) {
            IBEGen06aHeaderSerParameter that = (IBEGen06aHeaderSerParameter)anObject;
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.u)){
                return false;
            }
            if (!Arrays.equals(this.byteArrayU, that.byteArrayU)) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.v)){
                return false;
            }
            if (!Arrays.equals(this.byteArrayV, that.byteArrayV)) {
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
        this.u = pairing.getG1().newElementFromBytes(this.byteArrayU).getImmutable();
        this.v = pairing.getGT().newElementFromBytes(this.byteArrayV).getImmutable();
    }
}
