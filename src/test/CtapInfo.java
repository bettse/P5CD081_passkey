package test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The authenticatorGetInfo response, parsed the way a platform reads it. */
public class CtapInfo {

    public final List<String> versions = new ArrayList<>();
    public byte[] aaguid;

    /**
     * Options as sent. Absence is meaningful here and different from false, so
     * this deliberately records only what was present.
     */
    public final Map<String, Boolean> options = new LinkedHashMap<>();

    public long maxMsgSize;
    public long maxCredentialCountInList;
    public long maxCredentialIdLength;
    public final List<String> transports = new ArrayList<>();
    public final List<Long> pinProtocols = new ArrayList<>();
    public final List<Long> algorithms = new ArrayList<>();

    public boolean has(String option) {
        return options.containsKey(option);
    }

    public boolean isTrue(String option) {
        return Boolean.TRUE.equals(options.get(option));
    }

    public static CtapInfo parse(byte[] data) {
        Cbor c = new Cbor(data);
        CtapInfo info = new CtapInfo();

        int entries = c.expect(Cbor.MAP);
        for (int i = 0; i < entries; i++) {
            int key = (int) c.readInt();
            switch (key) {
                case 1: {
                    int n = c.expect(Cbor.ARRAY);
                    for (int j = 0; j < n; j++) {
                        info.versions.add(c.readText());
                    }
                    break;
                }
                case 3:
                    info.aaguid = c.readBytes();
                    break;
                case 4: {
                    int n = c.expect(Cbor.MAP);
                    for (int j = 0; j < n; j++) {
                        info.options.put(c.readText(), c.readBool());
                    }
                    break;
                }
                case 5:
                    info.maxMsgSize = c.readInt();
                    break;
                case 7:
                    info.maxCredentialCountInList = c.readInt();
                    break;
                case 8:
                    info.maxCredentialIdLength = c.readInt();
                    break;
                case 9: {
                    int n = c.expect(Cbor.ARRAY);
                    for (int j = 0; j < n; j++) {
                        info.transports.add(c.readText());
                    }
                    break;
                }
                case 6: {
                    int n = c.expect(Cbor.ARRAY);
                    for (int j = 0; j < n; j++) {
                        info.pinProtocols.add(c.readInt());
                    }
                    break;
                }
                case 10: {
                    int n = c.expect(Cbor.ARRAY);
                    for (int j = 0; j < n; j++) {
                        int fields = c.expect(Cbor.MAP);
                        for (int k = 0; k < fields; k++) {
                            String name = c.readText();
                            if (name.equals("alg")) {
                                info.algorithms.add(c.readInt());
                            } else {
                                c.readText();
                            }
                        }
                    }
                    break;
                }
                default:
                    throw new IllegalArgumentException("unexpected getInfo key " + key);
            }
        }
        if (c.remaining() != 0) {
            throw new IllegalArgumentException(c.remaining() + " trailing bytes");
        }
        return info;
    }
}
