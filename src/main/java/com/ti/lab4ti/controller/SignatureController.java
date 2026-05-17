package com.ti.lab4ti.controller;

import com.ti.lab4ti.service.RsaSignatureService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

@Controller
public class SignatureController {

    private final RsaSignatureService svc;

    public SignatureController(RsaSignatureService svc) {
        this.svc = svc;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("activeTab", "sign");
        return "index";
    }

    @PostMapping("/sign")
    public String sign(
            @RequestParam String p,
            @RequestParam String q,
            @RequestParam String d,
            @RequestParam MultipartFile file,
            Model model) {

        model.addAttribute("activeTab", "sign");
        model.addAttribute("inputP", p.trim());
        model.addAttribute("inputQ", q.trim());
        model.addAttribute("inputD", d.trim());

        try {
            if (p.isBlank() || q.isBlank() || d.isBlank()) {
                model.addAttribute("signError", "Заполните все поля (p, q, d)");
                return "index";
            }

            BigInteger bigP = new BigInteger(p.trim());
            BigInteger bigQ = new BigInteger(q.trim());
            BigInteger bigD = new BigInteger(d.trim());

            if (!svc.isPrime(bigP)) {
                model.addAttribute("signError", "p не является простым числом");
                return "index";
            }
            if (!svc.isPrime(bigQ)) {
                model.addAttribute("signError", "q не является простым числом");
                return "index";
            }
            if (bigP.equals(bigQ)) {
                model.addAttribute("signError", "p и q должны быть различными числами");
                return "index";
            }
            if (bigP.compareTo(BigInteger.TWO) < 0 || bigQ.compareTo(BigInteger.TWO) < 0) {
                model.addAttribute("signError", "p и q должны быть ≥ 2");
                return "index";
            }

            BigInteger n = svc.computeN(bigP, bigQ);
            BigInteger phi = svc.computePhi(bigP, bigQ);

            if (!svc.isValidPrivateKey(bigD, phi)) {
                model.addAttribute("signError",
                        "Неверный закрытый ключ d. Требования: 1 < d < φ(n)=" + phi + " и НОД(d, φ(n)) = 1");
                return "index";
            }

            if (file.getOriginalFilename() == null || file.getOriginalFilename().isBlank()) {
                model.addAttribute("signError", "Выберите файл для подписания");
                return "index";
            }

            BigInteger e = svc.computePublicExponent(bigD, phi);
            String content = new String(file.getBytes(), StandardCharsets.UTF_8);
            BigInteger hash = svc.computeHash(content, n);
            BigInteger signature = svc.sign(hash, bigD, n);
            String signedContent = svc.createSignedContent(content, signature);

            String origName = file.getOriginalFilename();
            String downloadName = (origName != null && origName.contains("."))
                    ? origName.substring(0, origName.lastIndexOf('.')) + "_signed.txt"
                    : (origName != null ? origName : "file") + "_signed.txt";

            model.addAttribute("signN", n.toString());
            model.addAttribute("signPhi", phi.toString());
            model.addAttribute("signE", e.toString());
            model.addAttribute("signHash", hash.toString());
            model.addAttribute("signSignature", signature.toString());
            model.addAttribute("signedContent", signedContent);
            model.addAttribute("downloadName", downloadName);
            model.addAttribute("signSuccess", true);

        } catch (NumberFormatException ex) {
            model.addAttribute("signError", "Ошибка формата числа: " + ex.getMessage());
        } catch (ArithmeticException ex) {
            model.addAttribute("signError", "Ошибка вычисления (возможно d не имеет обратного элемента mod φ(n)): " + ex.getMessage());
        } catch (Exception ex) {
            model.addAttribute("signError", "Ошибка: " + ex.getMessage());
        }

        return "index";
    }

    @PostMapping("/verify")
    public String verify(
            @RequestParam String e,
            @RequestParam String n,
            @RequestParam MultipartFile file,
            Model model) {

        model.addAttribute("activeTab", "verify");
        model.addAttribute("inputE", e.trim());
        model.addAttribute("inputN", n.trim());

        try {
            if (e.isBlank() || n.isBlank()) {
                model.addAttribute("verifyError", "Заполните все поля (e, n)");
                return "index";
            }

            if (file.isEmpty()) {
                model.addAttribute("verifyError", "Выберите файл для проверки");
                return "index";
            }

            BigInteger bigE = new BigInteger(e.trim());
            BigInteger bigN = new BigInteger(n.trim());

            if (bigE.compareTo(BigInteger.ONE) <= 0) {
                model.addAttribute("verifyError", "e должно быть > 1");
                return "index";
            }
            if (bigN.compareTo(BigInteger.TWO) <= 0) {
                model.addAttribute("verifyError", "n должно быть > 2");
                return "index";
            }

            String content = new String(file.getBytes(), StandardCharsets.UTF_8);
            String[] parts = svc.parseSignedContent(content);
            String message = parts[0];
            BigInteger signature = new BigInteger(parts[1]);

            BigInteger computedHash = svc.computeHash(message, bigN);
            BigInteger recoveredHash = svc.recoverHash(signature, bigE, bigN);
            boolean valid = computedHash.equals(recoveredHash);

            model.addAttribute("verifyComputedHash", computedHash.toString());
            model.addAttribute("verifyRecoveredHash", recoveredHash.toString());
            model.addAttribute("verifySignature", signature.toString());
            model.addAttribute("verifyMessage", message.length() > 500
                    ? message.substring(0, 500) + "..." : message);
            model.addAttribute("verifyValid", valid);
            model.addAttribute("verifyDone", true);

        } catch (NumberFormatException ex) {
            model.addAttribute("verifyError", "Ошибка формата числа: " + ex.getMessage());
        } catch (IllegalArgumentException ex) {
            model.addAttribute("verifyError", ex.getMessage());
        } catch (Exception ex) {
            model.addAttribute("verifyError", "Ошибка: " + ex.getMessage());
        }

        return "index";
    }
}
