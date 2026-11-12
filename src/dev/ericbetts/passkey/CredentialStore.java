package dev.ericbetts.passkey;

/**
 * A fixed bank of credential slots.
 *
 * Fixed because every slot's key pair is allocated at install time. Growing
 * on demand would mean allocating EEPROM during a registration, which is exactly
 * when a card is least able to fail gracefully.
 *
 * Lookup is a linear scan. With a handful of slots that is cheaper than any index
 * would be, and it keeps the search order stable, which getNextAssertion needs.
 */
public class CredentialStore {

    private final Credential[] slots;

    public CredentialStore() {
        slots = new Credential[Const.SLOTS];
        for (short i = (short) 0; i < Const.SLOTS; i++) {
            slots[i] = new Credential();
        }
    }

    public short size() {
        return Const.SLOTS;
    }

    public Credential get(short index) {
        return slots[index];
    }

    public short used() {
        short count = (short) 0;
        for (short i = (short) 0; i < Const.SLOTS; i++) {
            if (slots[i].isPresent()) {
                count++;
            }
        }
        return count;
    }

    public boolean isEmpty() {
        return used() == (short) 0;
    }

    public void clearAll() {
        for (short i = (short) 0; i < Const.SLOTS; i++) {
            if (slots[i].isPresent()) {
                slots[i].clear();
            }
        }
    }

    /**
     * Where a registration for this relying party and user should go.
     *
     * An existing credential for the same pair is replaced, which is what CTAP2
     * requires: a site re-registering the same user gets one credential, not two.
     * Otherwise the first free slot.
     *
     * On a single-slot card a new registration always replaces the old one. The
     * alternative is a card that refuses every registration after the first
     * until someone resets it, which is not a useful device. With more than one
     * slot a full card says so instead, because silently evicting a credential
     * the user still relies on would be worse than failing.
     *
     * @return the slot index, or -1 when the card is full
     */
    public short slotForRegistration(byte[] rpIdHash, short rpIdHashOff,
                                     byte[] userId, short userIdOff, short userIdLen) {
        if (Const.SLOTS == (short) 1) {
            return (short) 0;
        }
        if (userIdLen > (short) 0) {
            for (short i = (short) 0; i < Const.SLOTS; i++) {
                if (slots[i].matchesRp(rpIdHash, rpIdHashOff)
                        && slots[i].matchesUser(userId, userIdOff, userIdLen)) {
                    return i;
                }
            }
        }
        for (short i = (short) 0; i < Const.SLOTS; i++) {
            if (!slots[i].isPresent()) {
                return i;
            }
        }
        return (short) -1;
    }

    /**
     * The next slot at or after `from` holding a credential for this relying party.
     *
     * @return the slot index, or -1 when there are no more
     */
    public short findByRp(byte[] rpIdHash, short off, short from) {
        for (short i = from; i < Const.SLOTS; i++) {
            if (slots[i].matchesRp(rpIdHash, off)) {
                return i;
            }
        }
        return (short) -1;
    }

    /** The slot holding this credential id, or -1. */
    public short findByCredId(byte[] buf, short off) {
        for (short i = (short) 0; i < Const.SLOTS; i++) {
            if (slots[i].matchesCredId(buf, off)) {
                return i;
            }
        }
        return (short) -1;
    }

    public short countByRp(byte[] rpIdHash, short off) {
        short count = (short) 0;
        for (short i = (short) 0; i < Const.SLOTS; i++) {
            if (slots[i].matchesRp(rpIdHash, off)) {
                count++;
            }
        }
        return count;
    }
}
