package com.loadstar.demo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.loadstar.demo.EncryptUtils.HexToInt;

/**
 * Created by andrew on 2018/3/19.
 * 实现分组实现
 */
public class BucketUtils {
    /**
     *
     * @param id: 123456abc123456
     * @param salt : [B@270421f5
     * @param c_group_size: 0.6 控制组阈值
     * @return
     */
    public static boolean ab_split(String id, String salt, float c_group_size){

        String sha = EncryptUtils.encryptSHASalt(id,salt);

        float ab = (float) HexToInt(sha.substring(0,6))/0xFFFFFF;

        if (ab > c_group_size){
            return true; // 实验组
        }else{
            return false; // 控制组
        }
    }

    /**
     *
     * @param id
     * @param salt
     * @param w : 0.2 0.3 0.5
     * @return
     */
    public static int ab_split(String id, String salt, List<Float> w){

        double sum = 0.0;
        for (int i =0; i<w.size();i++) {
            sum += w.get(i);
        }

        int index = (int) EncryptUtils.HexToInt(
                EncryptUtils.encryptSHA(id).substring(35))%100+1;

        double cum = 0.0;

        for (int i =0; i<w.size();i++) {
            double ratio = w.get(i)/sum*100;

            if (index>cum && index<=cum+ratio) {
                return i;
            }
            cum += ratio;
        }
        return -1;
    }

    public static void main(String[] args){

        for (int i=0; i<10; i++)
            System.out.println(ab_split("123456abc123456","[B@270421f5",0.5f));

        List<Float> ws= new ArrayList<Float>();

        ws.add(new Float(0.3));
        ws.add(new Float(0.2));
        ws.add(new Float(0.5));

        int[] bucketsizearray = new int[3];
        for (int i=0; i<3; i++){
            bucketsizearray[i] = 0;
        }

        int bucket_index = 0;
        for (int i=0;i<10000; i++){

            bucket_index = ab_split("123456abc123456","[B@270421f5",ws);
            bucketsizearray[bucket_index]++;
        }
        String intArrayString = Arrays.toString(bucketsizearray);

        System.out.println(intArrayString);
    }
}
