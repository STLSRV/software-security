# Worksheet N — <Topic> (<X> hrs)

**Course:** Software Security (KOSEN69) · **Week N**
**Aligned to:** OWASP <Axx / API / LLM> · CWE <...>
**Signature game:** <name>

> ⚠️ Sandbox only. Attack only the provided targets. See `ETHICS.md`.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
|Siravit Thakaew|6631503041|15/08/2026|       |

---

## Part 2 — Lecture Questions
*Answer in your own words (3–5 sentences each).*

1. …
2. …
3. …
4. …
5. …

---

## Part 3 — Hands-on Lab (<minutes> min)

**Learning goals**
- …

**Prerequisites:** Docker, browser, (Burp Suite Community if needed)

**Environment setup**
```bash
# commands to stand up the target
```

**What to submit per task:** the payload/command used · a request/response or terminal **screenshot** · a 2–3 sentence **mitigation**.

### Task 0 — Onboarding (5 min)
- Confirm the target runs (screenshot).

### Task 1 — <name> (<n> min)
- **Goal:** …
- **Steps:** …
- **Deliverable:** payload + screenshot + mitigation

### Task 2 — … (<n> min)
*(add tasks to fill the session; end with a "defend / fix it" task)*

### Task N — Defend (fix the code)
- **Goal:** apply the secure version and prove the exploit now fails.
- **Deliverable:** before/after code + screenshot of failed exploit.

---

## Part 4 — Reflection
- Which CWE/OWASP category did each finding map to?
- One real-world breach that matches this vulnerability class.
- The single most effective mitigation, and why.

---

## Grading rubric (100)

| Criteria | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation tasks complete + evidence | 40 |
| Defense / fixes correct | 25 |
| Reflection + mitigation quality | 15 |

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
