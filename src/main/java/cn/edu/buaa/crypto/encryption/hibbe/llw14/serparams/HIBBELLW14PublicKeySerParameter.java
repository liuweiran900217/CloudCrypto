package cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE public key parameters.
 */
public class HIBBELLW14PublicKeySerParameter extends PairingKeySerParameter {

    private final int maxUser;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element h;
    private final byte[] byteArrayH;

    private transient Element[] us;
    private final byte[][] byteArraysUs;

    private transient Element X3;
    private final byte[] byteArrayX3;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

        public HIBBELLW14PublicKeySerParameter(PairingParameters parameters, Element g, Element h, Element[] u, Element X3, Element eggAlpha) {
            super(false, parameters);

            this.g = g.getImmutable();
            this.byteArrayG = this.g.toBytes();

            this.h = h.getImmutable();
            this.byteArrayH = this.h.toBytes();

            this.us = ElementUtils.cloneImmutable(u);
            this.byteArraysUs = PairingUtils.GetElementArrayBytes(this.us);

            this.X3 = X3.getImmutable();
            this.byteArrayX3 = this.X3.toBytes();

            this.eggAlpha = eggAlpha.getImmutable();
            this.byteArrayEggAlpha = this.eggAlpha.toBytes();

            this.maxUser = u.length;
        }

    public Element getG() { return this.g.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element[] getUs() { return this.us; }

    public Element getUsAt(int index) {
        return this.us[index].duplicate();
    }

    public Element getX3() { return this.X3.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    public int getMaxUser() { return this.maxUser; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW14PublicKeySerParameter) {
            HIBBELLW14PublicKeySerParameter that = (HIBBELLW14PublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.getH())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElementArray(this.us, that.getUs())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysUs, that.byteArraysUs)) {
                return false;
            }
            //Compare X3
            if (!PairingUtils.isEqualElement(this.X3, that.getX3())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayX3, that.byteArrayX3)) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.getEggAlpha())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG);
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH);
        this.us = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysUs, PairingUtils.PairingGroupType.G1);
        this.X3 = pairing.getG1().newElementFromBytes(this.byteArrayX3);
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha);
    }
}
