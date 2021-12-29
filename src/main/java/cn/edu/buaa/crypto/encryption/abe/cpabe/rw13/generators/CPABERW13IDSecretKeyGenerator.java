package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEIDSecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13IDSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class CPABERW13IDSecretKeyGenerator implements PairingKeyParameterGenerator {
    protected CPABEIDSecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters idKeyGenerationParameters) {
        this.parameter = (CPABEIDSecretKeyGenerationParameter) idKeyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        CPABERW13MasterSecretKeySerParameter masterSecretKeyParameter = (CPABERW13MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        CPABERW13PublicKeySerParameter publicKeyParameter = (CPABERW13PublicKeySerParameter)parameter.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameter.getId(),
                PairingUtils.PairingGroupType.Zr).getImmutable();
        Element r = pairing.getZr().newRandomElement().getImmutable();

        Element K0 = publicKeyParameter.getG().powZn(masterSecretKeyParameter.getAlpha())
                .mul(publicKeyParameter.getU().powZn(elementId).mul(publicKeyParameter.getH()).powZn(r))
                .getImmutable();
        Element K1 = publicKeyParameter.getG().powZn(r).getImmutable();
        return new CPABERW13IDSecretKeySerParameter(publicKeyParameter.getParameters(), K0, K1);
    }

}
