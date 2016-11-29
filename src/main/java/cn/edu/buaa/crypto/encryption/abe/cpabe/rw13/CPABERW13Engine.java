package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13;

import cn.edu.buaa.crypto.algebra.Engine;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters large-universe CP-ABE engine.
 */
public class CPABERW13Engine implements Engine{
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Rousekalis-Waters large-universe CP-ABE";

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
