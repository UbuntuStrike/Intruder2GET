🔍 Intruder2GET — Burp Suite Extension

Intruder2GET is a Burp Suite extension designed for advanced fuzzing workflows where a payload injected into one request influences the behavior or output of a different page or request.
💡 What It Does

    For each payload in a wordlist, the extension:

        Replaces all instances of §payload§ in a selected first request.

        Sends the modified request.

        Immediately sends a second request (unchanged).

        Logs both responses for each payload.

🧪 Ideal Use Case

Intruder2GET is especially useful when fuzzing a parameter that is reflected or acted upon in a different request or page—for example:

    When injecting into a request that sets a cookie, session, or context...

    ...and the effect (e.g. reflection, error, or execution) only appears in a follow-up request or page.

This is common in:

    Cross-site scripting (XSS)

    Authentication bypass

    IDOR and logic flaws

    Multi-step form testing

⚙️ How to Use

    In Proxy > HTTP History, select two requests:

        The first must contain §payload§ placeholders.

        The second is triggered after each injected request.

    Right-click → Send to Intruder2GET.

    Load a wordlist and start the attack.

    Watch both responses in the output window.
