package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10EncryptionGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Waters IBE encryption generator.
 */
public class IBELW10EncryptionGenerator implements PairingEncryptionGenerator {

    private IBELW10EncryptionGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (IBELW10EncryptionGenerationParameters)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        IBELW10PublicKeySerParameter publicKeyParameters = (IBELW10PublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(s).getImmutable();
        Element C0 = sessionKey.mul(this.params.getMessage()).getImmutable();

        Element C1 = publicKeyParameters.getU().powZn(elementId).mul(publicKeyParameters.getH()).powZn(s).getImmutable();
        Element C2 = publicKeyParameters.getG().powZn(s).getImmutable();

        return new IBELW10CiphertextSerParameter(publicKeyParameters.getParameters(), C0, C1, C2);
    }
}
