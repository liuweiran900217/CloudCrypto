package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Created by Weiran Liu on 2016/4/7.
 */
public class OORELSW10aIntermediateCiphertextParameters extends PairingCiphertextParameters {
    private final int length;
    private final Element C0;
    private final Element[] C1s;
    private final Element[] C2s;
    private final Element Cv1;
    private final Element Cv2;
    private final Element[] Is;
    private final Element Iv;
    private final Element[] ss;
    private final Element sv;
    private final Element s;
    private final AsymmetricKeyParameter chameleonHashSecretKey;
    private final ChameleonHashResultParameters hashParameters;

    public OORELSW10aIntermediateCiphertextParameters(
            PairingParameters pairingParameters,
            int length, Element C0, Element[] C1s, Element[] C2s, Element Cv1, Element Cv2,
            Element[] Is, Element Iv, Element[] ss, Element sv, Element s,
            AsymmetricKeyParameter chameleonHashSecretKey, ChameleonHashResultParameters hashParameters) {
        super(pairingParameters);
        this.length = length;
        this.C0 = C0;
        this.C1s = C1s;
        this.C2s = C2s;
        this.Cv1 = Cv1;
        this.Cv2 = Cv2;
        this.Is = Is;
        this.Iv = Iv;
        this.ss = ss;
        this.sv = sv;
        this.s = s;
        this.chameleonHashSecretKey = chameleonHashSecretKey;
        this.hashParameters = hashParameters;
    }
}
