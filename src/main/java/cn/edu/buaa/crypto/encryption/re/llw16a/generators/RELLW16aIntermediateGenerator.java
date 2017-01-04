package cn.edu.buaa.crypto.encryption.re.llw16a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.re.genparams.REIntermediateGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aIntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16a CPA-secure RE intermediate ciphertext generator.
 */
public class RELLW16aIntermediateGenerator implements PairingEncryptionGenerator {
    private REIntermediateGenerationParameter parameter;
    private RELLW16aPublicKeySerParameter publicKeyParameter;
    protected int n;
    protected Element sessionKey;
    protected Element s;
    protected Element C0;
    protected Element[] ss;
    protected Element[] xs;
    protected Element[] C1s;
    protected Element[] C2s;

    public void init(CipherParameters parameter) {
        this.parameter = (REIntermediateGenerationParameter) parameter;
        this.publicKeyParameter = (RELLW16aPublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    protected void computeEncapsulation() {
        this.n = parameter.getN();
        this.ss = new Element[n];
        this.xs = new Element[n];
        this.C1s = new Element[n];
        this.C2s = new Element[n];

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        this.s = pairing.getZr().newZeroElement().getImmutable();
        for (int i = 0; i < n; i++) {
            this.ss[i] = pairing.getZr().newRandomElement().getImmutable();
            this.xs[i] = pairing.getZr().newRandomElement().getImmutable();
            this.C1s[i] = publicKeyParameter.getGb().powZn(ss[i]).getImmutable();
            this.C2s[i] = publicKeyParameter.getGb2().powZn(xs[i]).mul(publicKeyParameter.getHb()).powZn(ss[i]).getImmutable();
            this.s = this.s.add(this.ss[i]).getImmutable();
        }
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        return new RELLW16aIntermediateSerParameter(publicKeyParameter.getParameters(), n, sessionKey, s,
                C0, ss, xs, C1s, C2s);
    }
}