package cn.edu.buaa.crypto.encryption.ibe.lw10.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Wateres composite-order IBE with full security.
 */
public class IBELW10MasterSecretKeySerParameter extends PairingKeySerParameter {

    private transient Element alpha;
    private final byte[] byteArrayAlpha;
    private transient Element g3Generator;
    private final byte[] byteArrayG3Generator;

    public IBELW10MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Element g3Generator) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.byteArrayAlpha = this.alpha.toBytes();

        this.g3Generator = g3Generator.getImmutable();
        this.byteArrayG3Generator = this.g3Generator.toBytes();
    }

    public Element getAlpha(){
        return this.alpha.duplicate();
    }

    public Element getG3Generator() { return this.g3Generator.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBELW10MasterSecretKeySerParameter) {
            IBELW10MasterSecretKeySerParameter that = (IBELW10MasterSecretKeySerParameter)anObject;
            //Compare alpha
            if (!(PairingUtils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayAlpha, that.byteArrayAlpha)){
                return false;
            }
            //Compare g3Generator
            if (!(PairingUtils.isEqualElement(this.g3Generator, that.getG3Generator()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG3Generator, that.byteArrayG3Generator)){
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
        this.alpha = pairing.getZr().newElementFromBytes(this.byteArrayAlpha).getImmutable();
        this.g3Generator = pairing.getG1().newElementFromBytes(this.byteArrayG3Generator).getImmutable();
    }
}
