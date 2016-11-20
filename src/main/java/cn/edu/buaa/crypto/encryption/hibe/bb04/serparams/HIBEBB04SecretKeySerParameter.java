package cn.edu.buaa.crypto.encryption.hibe.bb04.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Secret Key Parameters for Boneh-Boyen HIBE.
 */
public class HIBEBB04SecretKeySerParameter extends PairingKeySerParameter {

    private final String[] ids;
    private transient Element[] elementIds;
    private final byte[][] byteArraysElementIds;

    private transient Element d0;
    private final byte[] byteArrayD0;

    private transient Element[] ds;
    private final byte[][] byteArraysDs;

    public HIBEBB04SecretKeySerParameter(PairingParameters pairingParameters, String[] ids, Element[] elementIds, Element d0, Element[] ds) {
        super(true, pairingParameters);

        this.d0 = d0.getImmutable();
        this.byteArrayD0 = this.d0.toBytes();

        this.ds = ElementUtils.cloneImmutable(ds);
        this.byteArraysDs = PairingUtils.GetElementArrayBytes(this.ds);

        this.ids = ids;
        this.elementIds = ElementUtils.cloneImmutable(elementIds);
        this.byteArraysElementIds = PairingUtils.GetElementArrayBytes(this.elementIds);
    }

    public int getLength() { return this.ids.length; }

    public String getIdAt(int index) { return this.ids[index]; }

    public String[] getIds() { return this.ids; }

    public Element getElementIdAt(int index) { return this.elementIds[index].duplicate(); }

    public Element[] getElementIds() { return this.elementIds; }

    public Element getD0() { return this.d0.duplicate(); }

    public Element getDsAt(int index) { return this.ds[index].duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04SecretKeySerParameter) {
            HIBEBB04SecretKeySerParameter that = (HIBEBB04SecretKeySerParameter)anObject;
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
            //Compare d0
            if (!PairingUtils.isEqualElement(this.d0, that.getD0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD0, that.byteArrayD0)) {
                return false;
            }
            //Compare ds
            if (!PairingUtils.isEqualElementArray(this.ds, that.ds)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysDs, that.byteArraysDs)) {
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
        this.d0 = pairing.getG1().newElementFromBytes(this.byteArrayD0).getImmutable();
        this.elementIds = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysElementIds, PairingUtils.PairingGroupType.Zr);
        this.ds = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysDs, PairingUtils.PairingGroupType.G1);
    }
}
