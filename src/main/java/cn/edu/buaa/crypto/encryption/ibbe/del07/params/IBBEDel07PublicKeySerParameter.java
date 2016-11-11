package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Public key parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07PublicKeySerParameter extends PairingKeySerParameter {

    private final int maxBroadcastReceiver;
    private final Element w;
    private final Element v;
    private final Element[] hs;

    public IBBEDel07PublicKeySerParameter(PairingParameters parameters, Element w, Element v, Element[] hs) {
        super(false, parameters);

        this.w = w.getImmutable();
        this.v = v.getImmutable();

        this.hs = ElementUtils.cloneImmutable(hs);
        this.maxBroadcastReceiver = hs.length - 1;
    }

    public Element getW() { return this.w.duplicate(); }

    public Element getV() { return this.v.duplicate(); }

    public Element[] getHs() { return this.hs; }

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
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.getV())) {
                return false;
            }
            //Compare hs
            if (!PairingUtils.isEqualElementArray(this.hs, that.getHs())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
