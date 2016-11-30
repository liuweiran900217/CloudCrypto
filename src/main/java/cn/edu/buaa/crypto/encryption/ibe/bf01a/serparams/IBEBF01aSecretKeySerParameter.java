package cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE secret key parameter.
 */
public class IBEBF01aSecretKeySerParameter extends PairingKeySerParameter {
    private final String id;
    private transient Element elementId;
    private final byte[] byteArrayElementId;

    private transient Element d;
    private final byte[] byteArrayD;

    public IBEBF01aSecretKeySerParameter(PairingParameters pairingParameters, String id, Element elementId, Element d) {
        super(true, pairingParameters);

        this.d = d.getImmutable();
        this.byteArrayD = this.d.toBytes();

        this.id = id;
        this.elementId = elementId.getImmutable();
        this.byteArrayElementId = this.elementId.toBytes();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getD() { return this.d.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof IBEBF01aSecretKeySerParameter) {
            IBEBF01aSecretKeySerParameter that = (IBEBF01aSecretKeySerParameter)anOjbect;
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
            //Compare d
            if (!PairingUtils.isEqualElement(this.d, that.d)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD, that.byteArrayD)) {
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
        this.elementId = pairing.getG1().newElementFromBytes(this.byteArrayElementId).getImmutable();
        this.d = pairing.getG1().newElementFromBytes(this.byteArrayD).getImmutable();
    }
}
