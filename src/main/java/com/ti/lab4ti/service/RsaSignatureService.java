package com.ti.lab4ti.service;

import org.springframework.stereotype.Service;

import java.math.BigInteger;

@Service
public class RsaSignatureService {

    private static final BigInteger H0 = BigInteger.valueOf(100);
    public static final String SIGNATURE_SEPARATOR = "\n---SIGNATURE---\n";
    private static final String CYRILLIC_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

    private BigInteger charToMi(char c) {
        char upper = Character.toUpperCase(c);
        int idxCyr = CYRILLIC_ALPHABET.indexOf(upper);
        if (idxCyr >= 0) {
            return BigInteger.valueOf(idxCyr + 1);
        }
        int cp = c;
        if ((cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A)) {
            return BigInteger.valueOf(cp >= 0x61 ? cp - 0x20 : cp);
        }
        return BigInteger.valueOf(cp);
    }

    /**
     * Hash function 3.2: H_i = ((H_{i-1} + M_i) mod n)^2 mod n, H_0 = 100
     * Cyrillic А–Я → 1–33, Latin A–Z → ASCII 65–90, others → Unicode code point.
     */
    public BigInteger computeHash(String message, BigInteger n) {
        BigInteger h = H0;
        for (char c : message.toCharArray()) {
            BigInteger mi = charToMi(c);
            BigInteger t = h.add(mi).mod(n);
            h = t.multiply(t).mod(n);
        }
        return h;
    }

    /**
     * Fast modular exponentiation (binary method): base^exp mod mod
     */
    public BigInteger fastModPow(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);
        while (exp.signum() > 0) {
            if (exp.testBit(0)) {
                result = result.multiply(base).mod(mod);
            }
            exp = exp.shiftRight(1);
            base = base.multiply(base).mod(mod);
        }
        return result;
    }

    public BigInteger computeN(BigInteger p, BigInteger q) {
        return p.multiply(q);
    }

    public BigInteger computePhi(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    /**
     * Derive public exponent e as modular inverse of d: e*d ≡ 1 (mod phi)
     */
    public BigInteger computePublicExponent(BigInteger d, BigInteger phi) {
        return d.modInverse(phi);
    }

    /** S = m^d mod n */
    public BigInteger sign(BigInteger hash, BigInteger d, BigInteger n) {
        return fastModPow(hash, d, n);
    }

    /** Recover hash from signature: S^e mod n */
    public BigInteger recoverHash(BigInteger signature, BigInteger e, BigInteger n) {
        return fastModPow(signature, e, n);
    }

    public String createSignedContent(String original, BigInteger signature) {
        return original + SIGNATURE_SEPARATOR + signature.toString();
    }

    /**
     * Split signed file into [originalMessage, signatureString].
     * Throws IllegalArgumentException if separator not found.
     */
    public String[] parseSignedContent(String content) {
        int idx = content.lastIndexOf(SIGNATURE_SEPARATOR);
        if (idx < 0) {
            throw new IllegalArgumentException("Файл не содержит метки подписи '---SIGNATURE---'");
        }
        String message = content.substring(0, idx);
        String sig = content.substring(idx + SIGNATURE_SEPARATOR.length()).trim();
        return new String[]{message, sig};
    }

    public boolean isPrime(BigInteger n) {
        if (n.compareTo(BigInteger.TWO) < 0) return false;
        return n.isProbablePrime(50);
    }

    public boolean isValidPrivateKey(BigInteger d, BigInteger phi) {
        if (d.compareTo(BigInteger.ONE) <= 0) return false;
        if (d.compareTo(phi) >= 0) return false;
        return d.gcd(phi).equals(BigInteger.ONE);
    }
}
