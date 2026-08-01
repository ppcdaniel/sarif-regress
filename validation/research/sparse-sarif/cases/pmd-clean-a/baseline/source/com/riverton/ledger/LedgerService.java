package com.riverton.ledger;

final class LedgerService {
    void reconcile(Exception failure) {
        failure.printStackTrace();
    }

    int summarize(int credits, int debits) {
        return credits - debits;
    }
}
