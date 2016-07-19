package cn.edu.buaa.crypto.access;

/**
 * Created by Weiran Liu on 2016/7/18.
 */

public class UnsatisfiedAccessControlException extends Exception {

    public UnsatisfiedAccessControlException(String message){
        super(message);
    }
}
