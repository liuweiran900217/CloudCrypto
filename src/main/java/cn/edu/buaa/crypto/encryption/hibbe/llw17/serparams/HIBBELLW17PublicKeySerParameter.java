package cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE public key parameter.
 */
public class HIBBELLW17PublicKeySerParameter extends PairingKeySerParameter {

    private final int maxUser;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element h;
    private final byte[] byteArrayH;

    private transient Element[] us;
    private final byte[][] byteArraysUs;

    private transient Element uv;
    private final byte[] byteArrayUv;

    private transient Element X3;
    private final byte[] byteArrayX3;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

    public HIBBELLW17PublicKeySerParameter(PairingParameters parameters, Element g, Element h, Element[] u, Element uv, Element X3, Element eggAlpha) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.h = h.getImmutable();
        this.byteArrayH = this.h.toBytes();

        this.us = ElementUtils.cloneImmutable(u);
        this.byteArraysUs = PairingUtils.GetElementArrayBytes(this.us);

        this.uv = uv.getImmutable();
        this.byteArrayUv = this.uv.toBytes();

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

    public Element getUv() { return this.uv.duplicate(); }

    public Element getX3() { return this.X3.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    public int getMaxUser() { return this.maxUser; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW17PublicKeySerParameter) {
            HIBBELLW17PublicKeySerParameter that = (HIBBELLW17PublicKeySerParameter)anObject;
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
            //Compare uv
            if (!PairingUtils.isEqualElement(this.uv, that.getUv())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayUv, that.byteArrayUv)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
        this.us = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysUs, PairingUtils.PairingGroupType.G1);
        this.uv = pairing.getG1().newElementFromBytes(this.byteArrayUv).getImmutable();
        this.X3 = pairing.getG1().newElementFromBytes(this.byteArrayX3).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
    }
}
