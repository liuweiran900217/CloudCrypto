package cn.edu.buaa.crypto.chameleonhash;

import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.serialization.CHCZK04XMLSerializer;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;

import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2016/4/11.
 *
 * Chameleon hash engine manager, userd for choose the correct engine by the engine's name.
 */
public class CHEngineManager {
    public static CHEngine GetChameleonHashEngine(String name) {
        if (name.equals(CHCZK04Engine.SCHEME_NAME)) {
            return CHCZK04Engine.getInstance();
        } else {
            throw new InvalidParameterException("Cannot find Chameleon hash engine: " + name);
        }
    }

    public static ChameleonHashXMLSerializer GetChameleonHashXMLSerializer(String name) {
        if (name.equals(CHCZK04Engine.SCHEME_NAME)) {
            return CHCZK04XMLSerializer.getInstance();
        } else {
            throw new InvalidParameterException("Invalid Chameleon Hash Tags, find " + name);
        }
    }
}
