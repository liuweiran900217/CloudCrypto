package cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05SecretKeySerParameter extends PairingKeySerParameter {
    private final String[] ids;
    private transient Element[] elementIds;
    private final byte[][] byteArraysElementIds;

    private transient Element a0;
    private final byte[] byteArrayA0;

    private transient Element a1;
    private final byte[] byteArrayA1;

    private transient Element[] bs;
    private final byte[][] byteArraysBs;

    public HIBEBBG05SecretKeySerParameter(PairingParameters pairingParameters, String[] ids, Element[] elementIds,
                                          Element a0, Element a1, Element[] bs) {
        super(true, pairingParameters);

        this.a0 = a0.getImmutable();
        this.byteArrayA0 = this.a0.toBytes();

        this.a1 = a1.getImmutable();
        this.byteArrayA1 = this.a1.toBytes();

        this.bs = ElementUtils.cloneImmutable(bs);
        this.byteArraysBs = PairingUtils.GetElementArrayBytes(this.bs);

        this.ids = ids;
        this.elementIds = ElementUtils.cloneImmutable(elementIds);
        this.byteArraysElementIds = PairingUtils.GetElementArrayBytes(this.elementIds);
    }

    public int getLength() {
        return this.ids.length;
    }

    public String getIdAt(int index) { return this.ids[index]; }

    public String[] getIds() { return this.ids; }

    public Element getElementIdAt(int index) { return this.elementIds[index].duplicate(); }

    public Element[] getElementIds() { return this.elementIds; }

    public Element getA0() { return this.a0.duplicate(); }

    public Element getA1() { return this.a1.duplicate(); }

    public Element getBsAt(int index) { return this.bs[index].duplicate(); }

    public Element[] getBs() { return this.bs; }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof HIBEBBG05SecretKeySerParameter) {
            HIBEBBG05SecretKeySerParameter that = (HIBEBBG05SecretKeySerParameter)anOjbect;
            //Compare length
            if (this.getLength() != that.getLength()) {
                return false;
            }
            //Compare ids
            if (!Arrays.equals(this.ids, that.getIds())) {
                return false;
            }
            //Compare elementIds
            if (!PairingUtils.isEqualElementArray(this.elementIds, that.getElementIds())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysElementIds, that.byteArraysElementIds)) {
                return false;
            }
            //Compare a0
            if (!PairingUtils.isEqualElement(this.a0, that.getA0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayA0, that.byteArrayA0)) {
                return false;
            }
            //Compare a1
            if (!PairingUtils.isEqualElement(this.a1, that.getA1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayA1, that.byteArrayA1)) {
                return false;
            }
            //Compare bs
            if (!PairingUtils.isEqualElementArray(this.bs, that.getBs())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysBs, that.byteArraysBs)) {
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
        this.elementIds = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysElementIds, PairingUtils.PairingGroupType.Zr);
        this.a0 = pairing.getG1().newElementFromBytes(this.byteArrayA0).getImmutable();
        this.a1 = pairing.getG1().newElementFromBytes(this.byteArrayA1).getImmutable();
        this.bs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysBs, PairingUtils.PairingGroupType.G1);
    }
}
