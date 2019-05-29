package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu prime-order HIBBE encryption generator.
 */
public class HIBBELLW14EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private HIBBEEncryptionGenerationParameter params;

    private HIBBELLW14PublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element C0;
    private Element C1;

    public void init(CipherParameters params) {
        this.params = (HIBBEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (HIBBELLW14PublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] ids = this.params.getIds();
        if (ids.length != publicKeyParameter.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector set length");
        }
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element beta = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(beta).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(beta).getImmutable();
        this.C1 = publicKeyParameter.getH().getImmutable();
        for (int i=0; i<publicKeyParameter.getMaxUser(); i++){
            if (ids[i] != null){
                C1 = C1.mul(publicKeyParameter.getUsAt(i).powZn(elementIds[i])).getImmutable();
            }
        }
        C1 = C1.powZn(beta).getImmutable();
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C2 = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new HIBBELLW14CiphertextSerParameter(publicKeyParameter.getParameters(), C0, C1, C2);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new HIBBELLW14HeaderSerParameter(publicKeyParameter.getParameters(), C0, C1)
        );
    }
}
