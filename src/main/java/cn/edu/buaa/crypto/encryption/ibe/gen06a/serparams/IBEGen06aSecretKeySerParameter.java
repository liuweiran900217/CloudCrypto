package cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE secret key parameter.
 */
public class IBEGen06aSecretKeySerParameter extends PairingKeySerParameter {
    private final String id;
    private transient Element elementId;
    private final byte[] byteArrayElementId;

    private transient Element rId;
    private final byte[] byteArrayRId;

    private transient Element hId;
    private final byte[] byteArrayHId;

    public IBEGen06aSecretKeySerParameter(PairingParameters pairingParameters, String id, Element elementId, Element rId, Element hId) {
        super(true, pairingParameters);

        this.rId = rId.getImmutable();
        this.byteArrayRId = this.rId.toBytes();

        this.hId = hId.getImmutable();
        this.byteArrayHId = this.hId.toBytes();

        this.id = id;
        this.elementId = elementId.getImmutable();
        this.byteArrayElementId = this.elementId.toBytes();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getRId() { return this.rId.duplicate(); }

    public Element getHId() { return this.hId.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof IBEGen06aSecretKeySerParameter) {
            IBEGen06aSecretKeySerParameter that = (IBEGen06aSecretKeySerParameter)anOjbect;
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
            //Compare rId
            if (!PairingUtils.isEqualElement(this.rId, that.rId)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayRId, that.byteArrayRId)) {
                return false;
            }
            //Compare hId
            if (!PairingUtils.isEqualElement(this.hId, that.hId)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHId, that.byteArrayHId)) {
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
        this.rId = pairing.getZr().newElementFromBytes(this.byteArrayRId).getImmutable();
        this.hId = pairing.getG1().newElementFromBytes(this.byteArrayHId).getImmutable();
    }
}
