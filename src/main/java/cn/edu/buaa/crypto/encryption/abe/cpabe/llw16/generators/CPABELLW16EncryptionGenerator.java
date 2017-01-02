package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators.CPABEHW14EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-CP-ABE encryption generator.
 */
public class CPABELLW16EncryptionGenerator extends CPABEHW14EncryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private CPABELLW16PublicKeySerParameter publicKeyParameter;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private Element C01;
    private Element C02;
    private Element C03;
    private byte[] chameleonHash;
    private byte[] r;
}
