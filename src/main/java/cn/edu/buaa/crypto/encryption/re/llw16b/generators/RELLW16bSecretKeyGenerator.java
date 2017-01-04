package cn.edu.buaa.crypto.encryption.re.llw16b.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.genparams.RESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.generators.RELLW16aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bSecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE secret key generator.
 */
public class RELLW16bSecretKeyGenerator extends RELLW16aSecretKeyGenerator {
    public void init(KeyGenerationParameters keyGenerationParameter) {
        RESecretKeyGenerationParameter oriParameter = (RESecretKeyGenerationParameter)keyGenerationParameter;
        String id = oriParameter.getId();
        Pairing pairing = PairingFactory.getPairing(oriParameter.getPublicKeyParameter().getParameters());
        Element mappedElementId = PairingUtils.MapByteArrayToFirstHalfZr(pairing, id.getBytes());
        String mappedId = mappedElementId.toString();
        RESecretKeyGenerationParameter parameter = new RESecretKeyGenerationParameter(
                oriParameter.getPublicKeyParameter(),
                oriParameter.getMasterSecretKeyParameter(),
                mappedId
        );
        super.init(parameter);
    }

    public PairingKeySerParameter generateKey() {
        RELLW16aSecretKeySerParameter oriParameter = (RELLW16aSecretKeySerParameter) super.generateKey();
        return new RELLW16bSecretKeySerParameter(
                oriParameter.getParameters(),
                oriParameter.getId(),
                oriParameter.getElementId(),
                oriParameter.getD0(),
                oriParameter.getD1(),
                oriParameter.getD2());
    }
}
