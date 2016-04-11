package cn.edu.buaa.crypto.chameleonhash;

import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.serialization.CHCZK04XMLSerializer;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.CHKR00Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.serialization.CHKR00XMLSerializer;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;

import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2016/4/11.
 */
public class CHEngineManager {
    public static ChameleonHashXMLSerializer getChameleonHashXMLSerializer(String name) {
        if (name.equals(CHKR00Engine.SCHEME_NAME)) {
            return CHKR00XMLSerializer.getInstance();
        } else if (name.equals(CHCZK04Engine.SCHEME_NAME)) {
            return CHCZK04XMLSerializer.getInstance();
        } else {
            throw new InvalidParameterException("Invalid Chameleon Hash Tags, find " + name);
        }
    }
}
