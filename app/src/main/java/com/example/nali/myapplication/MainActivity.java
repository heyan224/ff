package com.example.nali.myapplication;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String publickey=  enkey("heyan224");
        System.out.println("######main111===="+publickey);
        //String data=dekey(publickey);

        String data=dekey(publickey);
        System.out.println("######main222==="+data);
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
