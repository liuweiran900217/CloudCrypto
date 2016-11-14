package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aCiphertextGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aCipherSerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters revocation encryption ciphertext / session key encapsulation pair generator.
 */
public class RELSW10AEncapsulationPairGenerator implements PairingEncapsulationPairGenerator {
    private RELSW10aCiphertextGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (RELSW10aCiphertextGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        RELSW10aPublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapToZr(pairing, ids);

        Element[] ss = new Element[this.params.getLength()];
        Element s = pairing.getZr().newZeroElement().getImmutable();
        for (int i=0; i<ss.length; i++) {
            ss[i] = pairing.getZr().newRandomElement().getImmutable();
            s = s.add(ss[i]).getImmutable();
        }

        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(s).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();
        Element C0 = publicKeyParameters.getG().powZn(s).getImmutable();
        Element[] C1s = new Element[this.params.getLength()];
        Element[] C2s = new Element[this.params.getLength()];
        for (int i=0; i<C1s.length; i++) {
            C1s[i] = publicKeyParameters.getGb().powZn(ss[i]).getImmutable();
            C2s[i] = publicKeyParameters.getGb2().powZn(elementIds[i]).mul(publicKeyParameters.getHb()).powZn(ss[i]).getImmutable();
        }

        return new PairingKeyEncapsulationSerPair(
                byteArraySessionKey,
                new RELSW10aCipherSerParameter(publicKeyParameters.getParameters(), this.params.getLength(), C0, C1s, C2s)
        );
    }
}
