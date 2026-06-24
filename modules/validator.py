# =============================================================================
# modules/validator.py  —  URLValidator
# =============================================================================
# PURPOSE:
#   This is the FIRST layer of defence. Before we run any detection logic,
#   we must make sure the input is a well-formed URL.  Accepting raw, un-
#   validated user input is a classic security mistake; a malformed string
#   can crash regex engines, confuse the ML feature extractor, or mask
#   malicious content behind encoding tricks.
#
# HOW IT WORKS (step-by-step):
#   1. Strip leading/trailing whitespace.
#   1.5. Refang threat intel URLs (hxxp -> http, [.] -> .).
#   2. If there is no scheme (http:// or https://) we prepend "http://" so
#      that urllib.parse can still split the URL into components correctly.
#   3. Use urllib.parse.urlparse() to decompose the URL into parts:
#        scheme | netloc (host+port) | path | params | query | fragment
#   4. Reject if the scheme is not http / https.
#   5. Reject if there is no netloc (domain / IP).
#   6. Return the normalised URL and a status flag.
# =============================================================================

from urllib.parse import urlparse


class URLValidator:
    """Sanitises and validates a raw URL string supplied by the user."""

    # Only these two schemes are considered valid for web browsing.
    ALLOWED_SCHEMES = {"http", "https"}

    def validate(self, raw_url: str) -> dict:
        """
        Validates a URL string.

        Parameters
        ----------
        raw_url : str
            The raw string typed (or pasted) by the user.

        Returns
        -------
        dict with keys:
            is_valid  (bool)   – True if the URL is usable.
            url       (str)    – The normalised URL (may differ from input).
            error     (str)    – Human-readable reason for rejection, or "".
        """

        # ── Step 1: Strip whitespace ─────────────────────────────────────────
        url = raw_url.strip()

        if not url:
            return self._fail("URL cannot be empty.")

        # ── Step 1.5: Refang Threat Intel URLs ───────────────────────────────
        url = url.replace('[.]', '.').replace('(.)', '.')
        if url.lower().startswith("hxxp://"):
            url = "http://" + url[7:]
        elif url.lower().startswith("hxxps://"):
            url = "https://" + url[8:]

        # ── Step 2: Inject a scheme if one is missing ────────────────────────
        # Convert to lowercase strictly for the prefix check to prevent 
        # auto-capitalized inputs (e.g., "Http://") from being prepended twice.
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url

        # ── Step 3: Parse into components ────────────────────────────────────
        try:
            parsed = urlparse(url)
        except Exception as exc:
            return self._fail(f"URL parsing error: {exc}")

        # ── Step 4: Validate scheme ──────────────────────────────────────────
        if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
            return self._fail(
                f"Unsupported scheme '{parsed.scheme}'. Only http/https allowed."
            )

        # ── Step 5: Validate netloc (domain / IP) ────────────────────────────
        if not parsed.netloc:
            return self._fail("No domain or IP found in URL.")

        # ── Step 6: Return success ────────────────────────────────────────────
        return {
            "is_valid": True,
            "url": url,          # normalised URL used in all downstream modules
            "error": "",
        }

    # ── Private helper ────────────────────────────────────────────────────────
    @staticmethod
    def _fail(reason: str) -> dict:
        return {"is_valid": False, "url": "", "error": reason}
