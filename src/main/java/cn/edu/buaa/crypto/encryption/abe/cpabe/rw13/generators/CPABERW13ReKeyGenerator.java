package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEReKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13ReKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Map;

import static cn.edu.buaa.crypto.utils.PairingUtils.PairingGroupType.G1;
import static cn.edu.buaa.crypto.utils.PairingUtils.PairingGroupType.Zr;

public class CPABERW13ReKeyGenerator implements PairingKeyParameterGenerator {

    protected CPABEReKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABEReKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        CPABERW13PublicKeySerParameter publicKeyParameter = (CPABERW13PublicKeySerParameter)parameter.getPublicKeyParameter();
        CPABERW13SecretKeySerParameter secretKeyParameter = (CPABERW13SecretKeySerParameter)parameter.getSecretKeyParameter();

        String ID = this.parameter.getID();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element t_ = pairing.getZr().newRandomElement().getImmutable();
        Element s_ = pairing.getZr().newRandomElement().getImmutable();

        Element id = PairingUtils.MapStringToGroup(pairing, ID, Zr);

        Element d0 = secretKeyParameter.getK0().mul(publicKeyParameter.getF().powZn(t_)).getImmutable();
        Element d1 = secretKeyParameter.getK1();
        Map<String, Element> d2s = secretKeyParameter.getK2s();
        Map<String, Element> d3s = secretKeyParameter.getK3s();
        Element d4 = PairingUtils.MapByteArrayToGroup(pairing, publicKeyParameter.getEggAlpha().powZn(s_).toBytes(), G1)
                .mul(publicKeyParameter.getG().powZn(t_)).getImmutable();
        Element d5 = publicKeyParameter.getU().powZn(id).mul(publicKeyParameter.getH()).powZn(s_).getImmutable();
        Element d6 = publicKeyParameter.getG().powZn(s_);

        return new CPABERW13ReKeySerParameter(publicKeyParameter.getParameters(), d0, d1, d2s, d3s, d4, d5, d6);
    }
}
