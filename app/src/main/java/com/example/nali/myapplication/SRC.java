package com.example.nali.myapplication;

import android.util.Log;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by nali on 2017/12/20.
 */

  class SRCMMain {
    public static void main(String[] args) {

       String publickey=  enkey("heyan224");

      //  String data=dekey(publickey);
        System.out.println("main111===="+publickey);
       // System.out.println("main222==="+data);
    }

   public static String enkey(String data){
       RSAPublicKey publicKey= RSA.getPublicKey();
       RSA rsa=new RSA(publicKey);
       String body=rsa.encryptByPublicKey(data);


       return body;

   }
   public static String dekey(String data){

       RSAPrivateKey privateKey=RSA.getPrivateKey();
       RSA rsa= new RSA( privateKey);
       String body=rsa.decryptByPrivateKey(data);
       return body;
   }


}
