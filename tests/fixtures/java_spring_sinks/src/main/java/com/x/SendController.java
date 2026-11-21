package com.x;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

// A Spring project must not turn every `.send(..)` into an SSRF sink.  Message
// brokers, SSE emitters, mailers and in-house services all have a `send`.
// Only the JDK HttpClient's `send` takes a URL.
@RestController
public class SendController {
    private KafkaTemplate<String, String> kafkaTemplate;
    private JavaMailSender mailSender;
    private NotificationService notifier;
    private final HttpClient http = HttpClient.newHttpClient();

    @PostMapping("/event")
    public String event(@RequestParam String payload) {
        kafkaTemplate.send("events", payload);
        notifier.send(payload);
        return "ok";
    }

    @PostMapping("/sse")
    public SseEmitter sse(@RequestParam String msg) throws Exception {
        SseEmitter emitter = new SseEmitter();
        emitter.send(msg);
        return emitter;
    }

    @GetMapping("/local-client")
    public String localClient(@RequestParam String target) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(target)).build();
        return client.send(req, BodyHandlers.ofString()).body();
    }

    @GetMapping("/field-client")
    public String fieldClient(@RequestParam String target) throws Exception {
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(target)).build();
        return http.send(req, BodyHandlers.ofString()).body();
    }

    @GetMapping("/builder-client")
    public String builderClient(@RequestParam String target) throws Exception {
        HttpClient client = HttpClient.newBuilder().build();
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(target)).build();
        return client.send(req, BodyHandlers.ofString()).body();
    }

    interface NotificationService {
        void send(String text);
    }
}
