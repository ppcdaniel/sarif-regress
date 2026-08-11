package com.riverton.recovery;

final class RecoveryCoordinator {
    void recover(Exception primaryFailure, Exception secondaryFailure) {
        primaryFailure.printStackTrace();
        secondaryFailure.printStackTrace();
    }

    void inspect(Exception failure) {
        failure.printStackTrace();
    }
}
