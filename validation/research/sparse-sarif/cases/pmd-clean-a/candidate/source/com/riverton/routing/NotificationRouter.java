package com.riverton.routing;

final class NotificationRouter {
    void routeEmail(Exception failure) {
        failure.printStackTrace();
    }

    void routeWebhook(Exception failure) {
        failure.printStackTrace();
    }
}
