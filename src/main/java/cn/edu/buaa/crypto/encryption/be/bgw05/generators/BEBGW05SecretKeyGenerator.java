package cn.edu.buaa.crypto.encryption.be.bgw05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BESecretKeyGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE secret key generator.
 */
public class BEBGW05SecretKeyGenerator implements PairingKeyParameterGenerator {
    private BESecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (BESecretKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        BEBGW05MasterSecretKeySerParameter masterSecretKeyParameter = (BEBGW05MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        BEBGW05PublicKeySerParameter publicKeyParameter = (BEBGW05PublicKeySerParameter)parameter.getPublicKeyParameter();
        int index = this.parameter.getIndex();
        if (index > publicKeyParameter.getMaxUserNum() || index < 1) {
            throw new IllegalArgumentException("Illegal index: " + index);
        }
        Element d = publicKeyParameter.getGsAt(index).powZn(masterSecretKeyParameter.getGamma()).getImmutable();
        return new BEBGW05SecretKeySerParameter(publicKeyParameter.getParameters(), index, d);
    }
}
