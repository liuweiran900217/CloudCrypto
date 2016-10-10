package cn.edu.buaa.crypto.utils;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by Weiran Liu on 2016/10/10.
 *
 * Timer used for scheme performance test.
 */
public class Timer {
    public enum FORMAT{
        SECOND, MILLI_SECOND, MICRO_SECOND, NANO_SECOND,
    }

    private static final int DEFAULT_MAX_NUM_TIMER = 10;
    private final int MAX_NUM_TIMER;

    private long[] timeRecorder;
    private boolean[] isTimerStart;
    private FORMAT[] outFormat;

    public static String nowTime() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");// �������ڸ�ʽ
        return df.format(new Date());
    }

    public Timer(){
        this.MAX_NUM_TIMER = DEFAULT_MAX_NUM_TIMER;
        this.timeRecorder = new long[MAX_NUM_TIMER];
        this.isTimerStart = new boolean[MAX_NUM_TIMER];
        this.outFormat = new FORMAT[MAX_NUM_TIMER];

        //set default format as millisecond
        for (int i=0; i<outFormat.length; i++){
            outFormat[i] = FORMAT.MILLI_SECOND;
        }
    }

    public Timer(int max_num_timer){
        this.MAX_NUM_TIMER = max_num_timer;
        this.timeRecorder = new long[MAX_NUM_TIMER];
        this.isTimerStart = new boolean[MAX_NUM_TIMER];
        this.outFormat = new FORMAT[MAX_NUM_TIMER];

        //set default format as millisecond
        for (int i=0; i<outFormat.length; i++){
            outFormat[i] = FORMAT.MILLI_SECOND;
        }
    }

    public void setFormat(int num, FORMAT format){
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        this.outFormat[num] = format;
    }

    public void start(int num) {
        //Ensure the timer now stops.
        assert(!isTimerStart[num]);
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        isTimerStart[num] = true;
        timeRecorder[num] = System.nanoTime();
    }

    public double stop(int num) {
        //Ensure the timer now starts.
        assert(isTimerStart[num]);
        //Ensure num less than MAX_NUM_TIMER
        assert(num >=0 && num < MAX_NUM_TIMER);

        long result = System.nanoTime() - timeRecorder[num];
        isTimerStart[num] = false;

        switch(outFormat[num]){
            case SECOND:
                return (double) result / 1000000000L;
            case MILLI_SECOND:
                return (double) result / 1000000L;
            case MICRO_SECOND:
                return (double) result / 1000L;
            case NANO_SECOND:
                return (double) result;
            default:
                return (double) result / 1000000L;
        }

    }
}
