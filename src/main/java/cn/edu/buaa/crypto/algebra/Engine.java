package cn.edu.buaa.crypto.algebra;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Generic engine
 */
public abstract class Engine {
    private final SecurityModel security_model;
    private final SecurityLevel security_level;
    private final String scheme_name;

    public enum SecurityModel {
        RandomOracle, Standard
    }

    public enum SecurityLevel {
        CPA, CCA2
    }

    public Engine(String schemeName, SecurityModel securityModel, SecurityLevel securityLevel) {
        this.scheme_name = schemeName;
        this.security_model = securityModel;
        this.security_level = securityLevel;
    }

    public String getEngineName() {
        return this.scheme_name;
    }

    SecurityLevel getSecurityLevel() {
        return this.security_level;
    }

    SecurityModel getSecurityModel() {
        return this.security_model;
    }
}
