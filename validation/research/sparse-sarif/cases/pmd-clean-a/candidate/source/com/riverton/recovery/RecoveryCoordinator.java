package com.riverton.recovery;

final class RecoveryCoordinator {
    void inspect(Exception failure) {
        failure.printStackTrace();
    }

    void recover(Exception primaryFailure, Exception secondaryFailure) {
        secondaryFailure.printStackTrace();
        primaryFailure.printStackTrace();
    }
}
