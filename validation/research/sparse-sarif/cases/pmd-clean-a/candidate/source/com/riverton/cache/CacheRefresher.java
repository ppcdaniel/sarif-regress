package com.riverton.cache;

import java.util.logging.Logger;

final class CacheRefresher {
    private final Logger logger = Logger.getLogger(CacheRefresher.class.getName());

    void refresh(Exception failure) {
        logger.warning(failure.getMessage());
    }
}
