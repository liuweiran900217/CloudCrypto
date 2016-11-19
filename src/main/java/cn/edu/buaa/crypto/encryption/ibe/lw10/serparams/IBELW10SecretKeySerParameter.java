package cn.edu.buaa.crypto.encryption.ibe.lw10.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE secret key parameters.
 */
public class IBELW10SecretKeySerParameter extends PairingKeySerParameter {

    private final String id;
    private transient Element elementId;
    private final byte[] byteArrayElementId;

    private transient Element k1;
    private final byte[] byteArrayK1;

    private transient Element k2;
    private final byte[] byteArrayK2;

    public IBELW10SecretKeySerParameter(PairingParameters pairingParameters, String id, Element elementId, Element k1, Element k2) {
        super(true, pairingParameters);

        this.k1 = k1.getImmutable();
        this.byteArrayK1 = this.k1.toBytes();

        this.k2 = k2.getImmutable();
        this.byteArrayK2 = this.k2.toBytes();

        this.id = id;
        this.elementId = elementId.getImmutable();
        this.byteArrayElementId = this.elementId.toBytes();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getK1() { return this.k1.duplicate(); }

    public Element getK2() { return this.k2.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof IBELW10SecretKeySerParameter) {
            IBELW10SecretKeySerParameter that = (IBELW10SecretKeySerParameter)anOjbect;
            //Compare id
            if (!this.id.equals(that.getId())) {
                return false;
            }
            //Compare elementId
            if (!PairingUtils.isEqualElement(this.elementId, that.getElementId())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayElementId, that.byteArrayElementId)) {
                return false;
            }
            //Compare k1
            if (!PairingUtils.isEqualElement(this.k1, that.getK1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayK1, that.byteArrayK1)) {
                return false;
            }
            //Compare k2
            if (!PairingUtils.isEqualElement(this.k2, that.getK2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayK2, that.byteArrayK2)) {
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
        this.elementId = pairing.getZr().newElementFromBytes(this.byteArrayElementId).getImmutable();
        this.k1 = pairing.getG1().newElementFromBytes(this.byteArrayK1).getImmutable();
        this.k2 = pairing.getG1().newElementFromBytes(this.byteArrayK2).getImmutable();
    }
}
