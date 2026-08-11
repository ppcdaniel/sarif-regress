package com.riverton.imports;

final class InvoiceImporter {
    void importFile(String path) {
        try {
            parse(path);
        } catch (RuntimeException failure) {
            failure.printStackTrace();
        }
    }

    private void parse(String path) {
        path.length();
    }
}
