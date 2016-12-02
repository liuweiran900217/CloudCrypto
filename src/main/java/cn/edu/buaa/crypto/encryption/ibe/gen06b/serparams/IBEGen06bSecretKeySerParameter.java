package cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams;

import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aSecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CCA2-secure IBE secret key parameter.
 */
public class IBEGen06bSecretKeySerParameter extends IBEGen06aSecretKeySerParameter {
    private transient Element rId2;
    private final byte[] byteArrayRId2;

    private transient Element hId2;
    private final byte[] byteArrayHId2;

    private transient Element rId3;
    private final byte[] byteArrayRId3;

    private transient Element hId3;
    private final byte[] byteArrayHId3;

    public IBEGen06bSecretKeySerParameter(PairingParameters pairingParameters, String id, Element elementId,
                                          Element rId, Element hId, Element rId2, Element hId2, Element rId3, Element hId3) {
        super(pairingParameters, id, elementId, rId, hId);

        this.rId2 = rId2.getImmutable();
        this.byteArrayRId2 = this.rId2.toBytes();

        this.hId2 = hId2.getImmutable();
        this.byteArrayHId2 = this.hId2.toBytes();

        this.rId3 = rId3.getImmutable();
        this.byteArrayRId3 = this.rId3.toBytes();

        this.hId3 = hId3.getImmutable();
        this.byteArrayHId3 = this.hId3.toBytes();
    }

    public Element getRId2() { return this.rId2.duplicate(); }

    public Element getHId2() { return this.hId2.duplicate(); }

    public Element getRId3() { return this.rId3.duplicate(); }

    public Element getHId3() { return this.hId3.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof IBEGen06bSecretKeySerParameter) {
            IBEGen06bSecretKeySerParameter that = (IBEGen06bSecretKeySerParameter)anOjbect;
            //Compare rId2
            if (!PairingUtils.isEqualElement(this.rId2, that.rId2)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayRId2, that.byteArrayRId2)) {
                return false;
            }
            //Compare hId2
            if (!PairingUtils.isEqualElement(this.hId3, that.hId3)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHId3, that.byteArrayHId3)) {
                return false;
            }
            //Compare rId3
            if (!PairingUtils.isEqualElement(this.rId3, that.rId3)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayRId3, that.byteArrayRId3)) {
                return false;
            }
            //Compare hId3
            if (!PairingUtils.isEqualElement(this.hId3, that.hId3)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHId3, that.byteArrayHId3)) {
                return false;
            }
            //compare supers
            return super.equals(anOjbect);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.rId2 = pairing.getZr().newElementFromBytes(this.byteArrayRId2).getImmutable();
        this.hId2 = pairing.getG1().newElementFromBytes(this.byteArrayHId2).getImmutable();
        this.rId3 = pairing.getZr().newElementFromBytes(this.byteArrayRId3).getImmutable();
        this.hId3 = pairing.getG1().newElementFromBytes(this.byteArrayHId3).getImmutable();
    }
}