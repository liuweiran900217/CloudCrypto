package cn.edu.buaa.crypto.algebra;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Generic engine
 */
public abstract class Engine {
    private final ProveSecModel provable_security_model;
    private final PayloadSecLevel payload_security_level;
    private final PredicateSecLevel predicate_security_level;
    private final String scheme_name;

    public enum ProveSecModel {
        RandomOracle, Standard
    }

    public enum PayloadSecLevel {
        CPA, CCA2
    }

    public enum PredicateSecLevel {
        NON_ANON, ANON,
    }

    public Engine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        this.scheme_name = schemeName;
        this.provable_security_model = proveSecModel;
        this.payload_security_level = payloadSecLevel;
        this.predicate_security_level = predicateSecLevel;
    }

    public String getEngineName() {
        return this.scheme_name;
    }

    PayloadSecLevel getPayloadSecLevel() {
        return this.payload_security_level;
    }

    ProveSecModel getProveSecModel() {
        return this.provable_security_model;
    }

    PredicateSecLevel getPredicateSecLevel() { return this.predicate_security_level; }
}
