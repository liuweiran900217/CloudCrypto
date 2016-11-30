package cn.edu.buaa.crypto.algebra;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Generic engine
 */
public interface Engine {
    enum SecurityLevel {
        CPA, CCA2
    }

    String getEngineName();

//    SecurityLevel getSecurityLevel();
}
