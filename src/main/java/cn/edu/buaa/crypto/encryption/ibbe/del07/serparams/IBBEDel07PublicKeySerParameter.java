package cn.edu.buaa.crypto.encryption.ibbe.del07.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Public key parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07PublicKeySerParameter extends PairingKeySerParameter {

    private final int maxBroadcastReceiver;

    private transient Element w;
    private final byte[] byteArrayW;

    private transient Element v;
    private final byte[] byteArrayV;

    private transient Element[] hs;
    private final byte[][] byteArraysHs;

    public IBBEDel07PublicKeySerParameter(PairingParameters parameters, Element w, Element v, Element[] hs) {
        super(false, parameters);

        this.w = w.getImmutable();
        this.byteArrayW = this.w.toBytes();

        this.v = v.getImmutable();
        this.byteArrayV = this.v.toBytes();

        this.hs = ElementUtils.cloneImmutable(hs);
        this.byteArraysHs = PairingUtils.GetElementArrayBytes(this.hs);

        this.maxBroadcastReceiver = hs.length - 1;
    }

    public Element getW() { return this.w.duplicate(); }

    public Element getV() { return this.v.duplicate(); }

    public Element getHsAt(int index) {
        return this.hs[index].duplicate();
    }

    public int getMaxBroadcastReceiver() { return this.maxBroadcastReceiver; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBBEDel07PublicKeySerParameter) {
            IBBEDel07PublicKeySerParameter that = (IBBEDel07PublicKeySerParameter)anObject;
            //Compare maximal broadcast receivers
            if (this.maxBroadcastReceiver != that.getMaxBroadcastReceiver()) {
                return false;
            }
            //Compare w
            if (!PairingUtils.isEqualElement(this.w, that.getW())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayW, that.byteArrayW)) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.getV())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayV, that.byteArrayV)) {
                return false;
            }
            //Compare hs
            if (!PairingUtils.isEqualElementArray(this.hs, that.hs)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysHs, that.byteArraysHs)) {
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
        this.w = pairing.getG1().newElementFromBytes(this.byteArrayW).getImmutable();
        this.v = pairing.getGT().newElementFromBytes(this.byteArrayV).getImmutable();
        this.hs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysHs, PairingUtils.PairingGroupType.G2);
    }
}
