# Simple Java JWT sign example

Months ago, I read an [article](https://medium.com/deno-the-complete-reference/java-vs-rust-how-faster-is-machine-code-compared-to-interpreted-code-for-jwt-sign-verify-fa6aeeabff58) comparing Rust to Java in a simple scenario of signing JWT tokens. To be honest, I expected Rust (a native language) to outperform Java (bytecode that must be handled by the JVM in order to generate native code), but not by as much as the article claims.

In the above article, the author claims that Rust performs 5.2 times better than Java, or more than 500%. This made me wonder if something in the article's scenario could be wrong.

Here you can see the Rust [app](https://github.com/pjgg/rustJwtExample) that I have developed based on the article snippets.

```Rust
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: u128,
    exp: u128,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let file_contents =
        fs::read_to_string("/home/pagonzal/Documents/workspace/rustExample/emails.json")
            .unwrap();
    let emails: Vec<String> = serde_json::from_str(&file_contents).unwrap();

    let mut i = 1;
    let mut idx = 0;
    let jwt_secret = env::var("JWT_SECRET").expect("$JWT_SECRET is not set");
    let jwt_encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());
    let jwt_decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let num_iterations = args[1].parse::<i32>().unwrap();
    let mut start_ts = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
    let validation = Validation::new(Algorithm::HS256);

    loop {
        let email = &emails[idx];
        idx += 1;
        let curr_ts = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
        let my_claims = Claims {
            sub: email.to_string(),
            iat: curr_ts,
            exp: curr_ts + 2 * 60 * 60 * 1000,
        };
        
        let token = match encode(&Header::default(), &my_claims, &jwt_encoding_key) {
            Ok(t) => t,
            Err(_) => panic!(),
        };
        //println!("Token: {}", token);
        let token_data = match decode::<Claims>(&token, &jwt_decoding_key, &validation) {
            Ok(c) => c,
            Err(err) => panic!("{}", err.to_string()),
        };
        if token_data.claims.sub != email.to_string() {
            panic!("email didn't match");
        }
        if idx >= emails.len() {
            idx = 0;
        }
        i += 1;
        if i > num_iterations {
            break;
        }
    }

    let end_ts = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
    let diff = end_ts - start_ts;
    println!("{}", diff);
}
```

On the other hand, I have completely rewritten the Java [application](https://github.com/pjgg/javaJwtSignExample/tree/main/src/main/java/com/example). It is doing exactly the same things, with the same third-party libraries as the original article, and following the same steps.
The main difference is that I have implemented a solution that actually uses the full hardware resources available. I mean, in the original article, the author states that they are running their scenarios on a 'MacBook Pro M2.' When I saw the results, my first impression was that they must be running everything in a single blocking thread. With this implementation, you will get almost the same performance on a Raspberry Pi with a single core. 

One of the main benefits of Java is how rich this language is when it comes to running multiple tasks in parallel and then joining or resuming all of these parallel tasks.

```Java
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
```

In the original article, they claim that they are running Java 21. If you are indeed running Java 21, then please try to use virtual threads (maybe this is not the best scenario, but...give it a try!) and run each task in a separate VThread. The article's implementation is a Java-style like Java 7. So, let's see how this code (real Java 21) performs against the Rust implementation:

## Environment:

- Fedora Linux 40 (Workstation Edition)
- Processor - AMD Ryzen™ 9 5950X × 32
- RAM - 64 GiB
- Java 21 (temurin)
- Rust 1.78.0  

## Scenario:

1 million iterations (generate 1 million JWTs with 100,000 random emails)

## Rust

Repo: https://github.com/pjgg/rustJwtExample

compile: `cargo build`

Don´t forget to export the RSA secret Key:
```shell
export JWT_SECRET="$(</home/yourUser/Documents/workspace/jwtSignExample/src/main/resources/private_key.pem)"
```

run: `cargo run --release 1000000`

## Java

Repo: https://github.com/pjgg/javaJwtSignExample/tree/main

compile: `mvn clean package`

run: `java -jar target/jwtSignExample-1.0-SNAPSHOT-shaded.jar`

## Scenario Results

| Java | Rust |
|------|------|
| 5865 | 10011|
| 5447 | 9996 |
| 5437 | 10042|
| 5479 | 10097|
| 5472 | 10021|

* Lower is better (total time in milliseconds in order to generate 1 mill of JWTs)

## Analysis

On the [original article](https://medium.com/deno-the-complete-reference/java-vs-rust-how-faster-is-machine-code-compared-to-interpreted-code-for-jwt-sign-verify-fa6aeeabff58), the author claims that Rust was 5.2 times faster than Java; however, after running his scenario on my machine and re-implementing the Java code with virtual threads, it looks like the result is quite different.
Based on what I see, Java is beating Rust in terms of JWTs per second (170,464 JWTs per second). Rust is doing pretty well, but the provided implementation is not really using the MacBook Pro M2. I tried to re-implement the provided solution in order to distribute the load between all the cores that we have without success. Hopefully the original author of this post will re-implement the
Rust solution for more efficiency; otherwise, and using his words,  we can conclude that **Java is 1.7 times faster than Rust**. 

**Winner: JAVA**

Thanks for reading this article!
