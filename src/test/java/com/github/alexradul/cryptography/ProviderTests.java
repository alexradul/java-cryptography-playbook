package com.github.alexradul.cryptography;

import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;

public class ProviderTests {
    @Test
    void listProvidersAndAlgorithms() {

        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName());
            System.out.println("*******************************************************");
            provider.keySet().forEach(System.out::println);
        }
    }
}
