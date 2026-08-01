package com.riverton.ledger;

final class LedgerService {
    int summarize(int credits, int debits) {
        return credits - debits;
    }

    void reconcile(Exception failure) {
        failure.printStackTrace();
    }
}
