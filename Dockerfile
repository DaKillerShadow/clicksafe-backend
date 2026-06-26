FROM python:3.11-slim

# ── System dependencies ───────────────────────────────────────────────────────
# The slim base strips nearly everything. Chrome headless needs all of these.
# Missing any one causes a silent WebDriverException on every deep scan.
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg curl unzip \
    # Core graphics + display (required even in --headless=new mode)
    libx11-6 libxext6 libxi6 libxtst6 libxss1 \
    libxrandr2 libxcursor1 libxcomposite1 libxdamage1 libxfixes3 \
    libxkbcommon0 libxkbcommon-x11-0 \
    # Font rendering
    libfontconfig1 libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
    # GTK / ATK (Selenium uses accessibility APIs to find DOM elements)
    libgtk-3-0 libatk1.0-0 libatk-bridge2.0-0 libatspi2.0-0 \
    # GPU / DRM (needed even with --disable-gpu; GBM is a hard requirement)
    libgbm1 libdrm2 \
    # Audio / CUPS (Chrome links against these at startup)
    libasound2 libcups2 \
    # NSS / glib (TLS and GLib runtime)
    libnss3 libglib2.0-0 \
    # dbus (Chrome launches a dbus session internally)
    dbus \
    && mkdir -p /etc/apt/keyrings \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub \
       | gpg --dearmor -o /etc/apt/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] \
       http://dl.google.com/linux/chrome/deb/ stable main" \
       > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── ChromeDriver — install at build time, matching installed Chrome version ───
# Using webdriver-manager at REQUEST time adds 2-5s to every deep scan and
# can fail on GitHub rate limits. Pre-installing here is faster and reliable.
RUN CHROME_VERSION=$(google-chrome --version | grep -oP '\d+\.\d+\.\d+\.\d+') \
    && CHROMEDRIVER_URL="https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip" \
    && wget -q "$CHROMEDRIVER_URL" -O /tmp/chromedriver.zip \
    && unzip -q /tmp/chromedriver.zip -d /tmp/chromedriver_dir \
    && mv /tmp/chromedriver_dir/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver \
    && chmod +x /usr/local/bin/chromedriver \
    && rm -rf /tmp/chromedriver.zip /tmp/chromedriver_dir \
    && echo "ChromeDriver $(chromedriver --version) installed."

WORKDIR /app

# Copy and install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# Copy project files
COPY . .

# Run the app with gunicorn binding to Render's dynamic PORT variable
CMD ["sh", "-c", "gunicorn -w 1 -b 0.0.0.0:${PORT:-5000} --timeout 120 --keep-alive 5 app:app"]
