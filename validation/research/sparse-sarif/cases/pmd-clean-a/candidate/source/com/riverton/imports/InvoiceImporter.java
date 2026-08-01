package com.riverton.imports;

final class InvoiceImporter {
    void importFile(String path) {
        String normalized = path.trim();
        try {
            parse(normalized);
        } catch (RuntimeException failure) {
            failure.printStackTrace();
        }
    }

    private void parse(String path) {
        path.length();
    }
}
