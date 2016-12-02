package cn.edu.buaa.crypto.encryption.be.bgw05.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE public key parameter.
 */
public class BEBGW05PublicKeySerParameter extends PairingKeySerParameter {
    private final int maxUserNum;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element[] gs;
    private final byte[][] byteArraysGs;

    private transient Element v;
    private final byte[] byteArrayV;

    public BEBGW05PublicKeySerParameter(PairingParameters pairingParameters, int maxUserNum, Element g, Element[] gs, Element v) {
        super(true, pairingParameters);

        this.maxUserNum = maxUserNum;

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.gs = ElementUtils.cloneImmutable(gs);
        this.byteArraysGs = PairingUtils.GetElementArrayBytes(this.gs);

        this.v = v.getImmutable();
        this.byteArrayV = this.v.toBytes();
    }

    public int getMaxUserNum() { return this.maxUserNum; }

    public Element getG() { return this.g.duplicate(); }

    public Element getGsAt(int index) {
        return this.gs[index].duplicate();
    }

    public Element getV() {
        return this.v.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BEBGW05PublicKeySerParameter) {
            BEBGW05PublicKeySerParameter that = (BEBGW05PublicKeySerParameter) anObject;
            //compare maxUserNum
            if (this.maxUserNum != that.maxUserNum) {
                return false;
            }
            //compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //compare gs
            if (!PairingUtils.isEqualElementArray(this.gs, that.gs)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysGs, that.byteArraysGs)) {
                return false;
            }
            //compare v
            if (!PairingUtils.isEqualElement(this.v, that.v)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.gs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysGs, PairingUtils.PairingGroupType.G1);
        this.v = pairing.getG1().newElementFromBytes(this.byteArrayV).getImmutable();
    }
}