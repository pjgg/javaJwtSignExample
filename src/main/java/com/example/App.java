package com.example;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.tools.javac.Main;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;

public class App {

    private final static int TOTAL_ITERATIONS = 1000000;
    private final static boolean VIRTUAL_THREADS_ENABLED = true;

    public static void main(String[] args) throws Exception {
        int amountOfThreads = Runtime.getRuntime().availableProcessors();
        Gson gson = new Gson();
        Type listType = new TypeToken<List<String>>() {
        }.getType();
        String content = getFileContent("emails.json");
        List<String> emails = gson.fromJson(content, listType);
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);

        String privateKey = getFileContent("private_key.pem");
        SecretKey key = Keys.hmacShaKeyFor(privateKey.getBytes());

        AtomicInteger totalOp = new AtomicInteger(0);

        Runnable runnableTask = () -> {
            for(int i = 0; i < TOTAL_ITERATIONS; i++) {
                String email = emails.get(generateRandomPosition(99999));
                long currTS = System.currentTimeMillis();
                String jwt = Jwts.builder()
                        .issuedAt(new Date(currTS))
                        .expiration(new Date(currTS + 2 * 60 * 60 * 1000))
                        .subject(email)
                        .signWith(key)
                        .compact();
                Jws<Claims> claims = Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseSignedClaims(jwt);
                if (!email.equals(claims.getPayload().getSubject())) {
                    System.exit(1);
                }

                int currentTotalOp = totalOp.getAndIncrement();
                if(currentTotalOp >= TOTAL_ITERATIONS) {
                    break;
                }
            }
        };

        List<Thread> threads = new ArrayList<>(amountOfThreads);
        for(int i = 0; i < amountOfThreads; i++) {
            Thread thread = launchTask(runnableTask);
            threads.add(thread);
        }

        long startTS = System.currentTimeMillis();
        for(Thread thread : threads) {
            thread.join();
        }

        long endTS = System.currentTimeMillis();
        long diff = endTS - startTS;
        System.out.println(diff);
    }

    private static Thread launchTask(Runnable runnableTask) {
        if(VIRTUAL_THREADS_ENABLED) {
            return Thread.startVirtualThread(runnableTask);
        } else {
            Thread thread = new Thread(runnableTask);
            thread.start();
            return thread;
        }
    }

    private static String getFileContent(String resourcePath) throws IOException {
        ClassLoader classLoader = Main.class.getClassLoader();

        try (InputStream inputStream = classLoader.getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new IllegalArgumentException("File not found: " + resourcePath);
            }

            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
            String content = scanner.hasNext() ? scanner.next() : "";
            return content;
        }
    }

    public static int generateRandomPosition(int max) {
        Random random = new Random();
        int randomNumber = random.nextInt(max + 1);
        return randomNumber;
    }
}