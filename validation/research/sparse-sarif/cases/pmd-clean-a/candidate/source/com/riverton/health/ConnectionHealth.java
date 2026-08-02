package com.riverton.health;

final class ConnectionHealth {
    void report(Exception failure) {
        failure.printStackTrace();
    }
}
