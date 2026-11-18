package com.dooh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class TargetParserTest {

    @Test
    void acceptsIpHostAndCidr() {
        TargetParser.Result r = TargetParser.parse(List.of("203.0.113.10", "# comment", "", "Example.COM", "198.51.100.0/30"));
        assertTrue(r.errors.isEmpty(), r.errors.toString());
        assertEquals(List.of("203.0.113.10", "example.com", "198.51.100.1", "198.51.100.2"), r.targets);
    }

    @Test
    void rejectsCommandInjectionAttempts() {
        for (String bad : List.of("1.2.3.4 & del C:\\x", "1.2.3.4; rm -rf /", "$(reboot)", "1.2.3.4 | calc",
                "`id`", "-config /etc/passwd", "http://1.2.3.4", "1.2.3.4:5555", "a b", "1.2.3.4\"")) {
            TargetParser.Result r = TargetParser.parse(List.of(bad));
            assertFalse(r.errors.isEmpty(), "should reject: " + bad);
            assertTrue(r.targets.isEmpty(), "must not keep: " + bad);
        }
    }

    @Test
    void rejectsMulticastBroadcastAndBadAddresses() {
        for (String bad : List.of("224.0.0.251", "239.255.255.250", "255.255.255.255", "0.0.0.0", "256.1.1.1", "1.2.3", "1.2.3.4/33")) {
            assertFalse(TargetParser.parse(List.of(bad)).errors.isEmpty(), "should reject: " + bad);
        }
    }

    @Test
    void limitsCidrSizeAndSkipsNetworkAndBroadcast() {
        assertFalse(TargetParser.parse(List.of("10.0.0.0/16")).errors.isEmpty());
        TargetParser.Result r = TargetParser.parse(List.of("192.168.1.0/24"));
        assertEquals(254, r.targets.size());
        assertEquals("192.168.1.1", r.targets.get(0));
        assertEquals("192.168.1.254", r.targets.get(253));
    }

    @Test
    void removesDuplicatesKeepingOrder() {
        TargetParser.Result r = TargetParser.parse(List.of("192.0.2.5", "192.0.2.4", "192.0.2.5"));
        assertEquals(List.of("192.0.2.5", "192.0.2.4"), r.targets);
    }
}
