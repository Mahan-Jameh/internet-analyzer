"""
i18n_fa_diag.py
===============
Persian templates for the messages produced by the layered diagnostic engine
(``app/diag``) and the modules built on it. Merged into ``DYNAMIC_FA`` by
``app.i18n_fa`` - the format is identical (``{}`` in the key is a varying value,
``{1}``, ``{2}`` ... in the Persian text refer to those values in order).

Technical terms stay in Latin letters, as Persian-speaking network engineers write them.
Wording keeps the same hedging as the English text: "ممکن است", "محتمل", "نشانه‌ای احتمالی".
"""

from __future__ import annotations

DIAG_FA: dict[str, str] = {
    # ------------------------------------------------ report layers / headline
    "Failing sites: {}": "سایت‌های ناموفق: {1}",
    "Control sites that work: {}": "سایت‌های شاهدِ سالم: {1}",
    "Ping failed: {}": "ping ناموفق بود: {1}",
    "Resolvers returning an outlying answer: {}": "resolverهایی که پاسخ متفاوت دادند: {1}",
    "TCP/{} to {} is reachable": "TCP/{1} به {2} در دسترس است",
    "No handshake to {} completed": "هیچ handshake ای با {1} کامل نشد",
    "DNS filtering/poisoning": "فیلترینگ/مسموم‌سازی DNS",
    "SNI-based filtering": "فیلترینگ مبتنی بر SNI",
    "ISP congestion": "ازدحام در شبکه‌ی ISP",
    "Overloaded device": "دستگاه پرباری که کند شده",
    "Server-side issue": "مشکل سمت سرور",
    "ok": "موفق",
    "reset": "ریست",
    "eof": "بسته شدن ناگهانی اتصال",
    "timeout": "بدون پاسخ (timeout)",
    "(no SNI)": "(بدون SNI)",
    "alert": "هشدار TLS (alert)",
    "the TLS handshake": "TLS handshake",
    "TLS handshake": "TLS handshake",
    "the TCP connection": "اتصال TCP",
    "Local gateway": "gateway محلی",
    "DNS resolution": "تبدیل نام (DNS)",
    "TCP connectivity": "اتصال TCP",
    "TLS connectivity": "اتصال TLS",
    "HTTP/HTTPS": "HTTP/HTTPS",
    "ICMP (ping)": "ICMP (ping)",
    "UDP probes": "آزمون‌های UDP",
    "Latency": "تأخیر",
    "Packet loss": "از دست رفتن بسته",
    "this is not a port-availability problem": "این مشکل در دسترس بودن پورت نیست",
    "TLS with SNI failed; TLS without SNI succeeded": "TLS با SNI ناموفق بود؛ TLS بدون SNI موفق شد",
    "VPN/tunnel adapter": "کارت VPN/تونل",
    "Proxy": "پروکسی",
    "Detected: {}": "تشخیص داده شد: {1}",
    "Likely: {}": "محتمل: {1}",
    "Possible: {}": "ممکن است: {1}",
    "Inconclusive: {}": "نتیجه‌ی قطعی نیست: {1}",
    "Evidence: {}": "شواهد: {1}",
    "Note: {}": "نکته: {1}",
    "Possible causes: {}": "علل ممکن: {1}",
    "No analysis available.": "تحلیلی در دسترس نیست.",
    "Not enough measurements to judge the connection.": "اندازه‌گیری کافی برای قضاوت درباره‌ی اتصال وجود ندارد.",
    "The connection works only partly or with problems.": "اتصال فقط تا حدی یا با مشکل کار می‌کند.",
    "No connectivity problem was detected.": "مشکل اتصالی دیده نشد.",
    "The Internet connection appears to be unavailable.": "به نظر می‌رسد اتصال اینترنت در دسترس نیست.",
    "{}: working": "{1}: سالم",
    "{}: failing": "{1}: ناموفق",
    "{}: partially working": "{1}: تا حدی کار می‌کند",
    "{} connectivity: available": "اتصال {1}: برقرار",
    "{} connectivity: not working": "اتصال {1}: کار نمی‌کند",
    "{}: not configured": "{1}: پیکربندی نشده",

    "IPv6 is configured on this computer, but connections to external IPv6 hosts failed. Programs that prefer IPv6 may be slow to fall back to IPv4; the router or ISP may not provide working IPv6.":
        "IPv6 روی این رایانه پیکربندی شده، ولی اتصال به میزبان‌های IPv6 بیرونی ناموفق بود. برنامه‌هایی که IPv6 را ترجیح می‌دهند ممکن است دیر به IPv4 برگردند؛ شاید روتر یا ISP از IPv6 سالم پشتیبانی نمی‌کند.",
    "Available": "برقرار",
    "Not configured": "پیکربندی نشده",
    "Configured, but no Internet access": "پیکربندی شده، ولی بدون دسترسی به اینترنت",
    "Unknown": "نامشخص",

    # ------------------------------------------------ correlation: titles
    "Internet appears unavailable: every external probe failed":
        "اینترنت در دسترس به نظر نمی‌رسد: همه‌ی آزمون‌های بیرونی ناموفق بودند",
    "Local network problem: the gateway and all external targets are unreachable":
        "مشکل شبکه‌ی محلی: gateway و همه‌ی مقصدهای بیرونی در دسترس نیستند",
    "DNS resolution is failing": "تبدیل نام به آدرس (DNS) ناموفق است",
    "The system's DNS resolver is failing while public resolvers answer":
        "DNS resolver سیستم ناموفق است در حالی که resolverهای عمومی پاسخ می‌دهند",
    "DNS answers differ between resolvers (possible DNS interference)":
        "پاسخ‌های DNS بین resolverها متفاوت است (احتمال دخالت در DNS)",
    "TCP connections are failing (firewall, filtering or routing issue)":
        "اتصال‌های TCP ناموفق‌اند (مشکل فایروال، فیلترینگ یا مسیریابی)",
    "TLS connectivity problem (TCP works, the TLS handshake does not)":
        "مشکل اتصال TLS (TCP کار می‌کند ولی handshake انجام نمی‌شود)",
    "Filtering that depends on the TLS server name (SNI)": "فیلترینگ وابسته به نام سرور TLS (SNI)",
    "ICMP echo (ping) is blocked or unavailable; Internet connectivity appears functional":
        "ICMP echo (ping) مسدود یا در دسترس نیست؛ ولی اتصال اینترنت سالم به نظر می‌رسد",
    "IPv6 is not configured on this connection (IPv4 works)": "IPv6 روی این اتصال پیکربندی نشده است (IPv4 کار می‌کند)",
    "IPv6 appears configured but does not reach the Internet while IPv4 works":
        "IPv6 پیکربندی شده به نظر می‌رسد ولی به اینترنت نمی‌رسد، در حالی که IPv4 کار می‌کند",
    "Network quality is degraded (high latency or packet loss)":
        "کیفیت شبکه افت کرده است (تأخیر زیاد یا از دست رفتن بسته)",
    "The path MTU is reduced ({} bytes instead of {})": "MTU مسیر کاهش یافته است ({1} بایت به‌جای {2})",
    "Some sites fail at {} while control sites work": "برخی سایت‌ها در لایه‌ی {1} ناموفق‌اند در حالی که سایت‌های شاهد کار می‌کنند",
    "{} detected; its routing may influence the results of other tests":
        "{1} شناسایی شد؛ مسیریابی آن ممکن است روی نتیجه‌ی آزمون‌های دیگر اثر بگذارد",
    "TCP connection did not complete": "اتصال TCP کامل نشد",
    "TLS handshake failed": "TLS handshake ناموفق بود",
    "name resolution (DNS)": "تبدیل نام (DNS)",
    "the TCP connection": "اتصال TCP",
    "the TLS handshake": "TLS handshake",
    "the HTTP request": "درخواست HTTP",

    # ------------------------------------------------ correlation: evidence / causes / caveats
    "No external probe succeeded ({} probes with a definite result).":
        "هیچ آزمون بیرونی موفق نبود ({1} آزمون با نتیجه‌ی مشخص).",
    "The local gateway also did not respond.": "gateway محلی هم پاسخ نداد.",
    "The local gateway responds, so the problem is likely beyond your router.":
        "gateway محلی پاسخ می‌دهد، پس مشکل احتمالاً فراتر از روتر شماست.",
    "Local network/Wi-Fi/cable problem": "مشکل شبکه‌ی محلی / Wi-Fi / کابل",
    "ISP outage": "قطعی سمت ISP",
    "Router or modem not connected upstream": "روتر یا مودم به بالادست متصل نیست",
    "The system resolver failed for {} different names.": "resolver سیستم برای {1} نام مختلف ناموفق بود.",
    "Direct queries to public resolvers succeeded": "پرس‌وجوی مستقیم به resolverهای عمومی موفق بود",
    "IP-level connectivity works, so the Internet itself is reachable.":
        "اتصال در سطح IP کار می‌کند، پس خود اینترنت در دسترس است.",
    "ISP/router DNS server problem": "مشکل DNS server مربوط به ISP یا روتر",
    "DNS filtering of the configured resolver": "فیلترینگ DNS روی resolver تنظیم‌شده",
    "Configured DNS server unreachable or broken": "DNS server تنظیم‌شده در دسترس نیست یا خراب است",
    "DNS filtering or interference": "فیلترینگ یا دخالت در DNS",
    "Resolvers returning an outlying answer": "resolverهایی که پاسخ متفاوت می‌دهند",
    "CDN or geo-based answers (a normal cause)": "پاسخ‌های وابسته به CDN یا موقعیت جغرافیایی (علتی عادی)",
    "Different answers are common for CDN-hosted sites, so this is only a hint.":
        "پاسخ‌های متفاوت برای سایت‌های پشت CDN رایج است، پس این فقط یک اشاره است.",
    "ICMP echo works, so the host/path is up but TCP is not getting through.":
        "ICMP echo کار می‌کند، پس میزبان/مسیر برقرار است ولی TCP عبور نمی‌کند.",
    "The failure repeated on retry.": "ناموفق بودن در تلاش مجدد هم تکرار شد.",
    "Firewall or ISP filtering of these ports": "فیلتر شدن این پورت‌ها توسط فایروال یا ISP",
    "Routing problem towards the target": "مشکل مسیریابی به سمت مقصد",
    "Remote host not accepting connections": "میزبان مقصد اتصال نمی‌پذیرد",
    "A timeout is not proof that the port is closed or filtered.":
        "تایم‌اوت دلیلی بر بسته یا فیلتر بودن پورت نیست.",
    "DNS and TCP/443 succeeded for these targets.": "DNS و TCP/443 برای این مقصدها موفق بود.",
    "HTTPS requests failed as well, which is consistent with a TLS-level problem.":
        "درخواست‌های HTTPS هم ناموفق بودند که با مشکلی در سطح TLS سازگار است.",
    "The handshake failed on every attempt.": "handshake در همه‌ی تلاش‌ها ناموفق بود.",
    "TLS interception or filtering on the path": "رهگیری یا فیلترینگ TLS در مسیر",
    "TLS negotiation problem": "مشکل در مذاکره‌ی TLS",
    "A server that rejects unknown names (less likely)": "سروری که نام‌های ناشناخته را رد می‌کند (کم‌احتمال‌تر)",
    "This comparison is evidence, not proof.": "این مقایسه شاهد است، نه مدرک قطعی.",
    "TCP or HTTPS connections succeeded.": "اتصال‌های TCP یا HTTPS موفق بودند.",
    "Firewall dropping ICMP": "فایروال که ICMP را دور می‌اندازد",
    "Target does not answer ping": "مقصد به ping پاسخ نمی‌دهد",
    "Ping failure alone does not mean the Internet is down.": "ناموفق بودن ping به‌تنهایی به معنی قطع بودن اینترنت نیست.",
    "No usable global IPv6 address or route was found.": "آدرس یا مسیر IPv6 عمومی قابل استفاده‌ای پیدا نشد.",
    "IPv4 reaches the Internet.": "IPv4 به اینترنت می‌رسد.",
    "IPv6 is configured but external IPv6 probes failed.": "IPv6 پیکربندی شده ولی آزمون‌های IPv6 بیرونی ناموفق بود.",
    "ISP/router IPv6 misconfiguration": "پیکربندی نادرست IPv6 در ISP یا روتر",
    "IPv6 blocked upstream": "IPv6 در بالادست مسدود شده است",
    "Browsers fall back to IPv4, so impact is often small.": "مرورگرها به IPv4 برمی‌گردند، پس اثر معمولاً کم است.",
    "{}: avg {} ms, loss {}%": "{1}: میانگین {2} میلی‌ثانیه، از دست رفتن {3}٪",
    "TCP connections to the Internet succeed, so ports are reachable.":
        "اتصال‌های TCP به اینترنت موفق است، پس پورت‌ها در دسترس‌اند.",
    "; this is not a port-availability problem": "؛ این مشکل در دسترس بودن پورت نیست",
    "Congested or weak Wi-Fi/link": "ازدحام یا ضعف Wi-Fi/لینک",
    "{} (+{} more)": "{1} (+{2} مورد دیگر)",
    "TCP connection did not complete: {}": "اتصال TCP کامل نشد: {1}",
    "TLS handshake failed: {}": "TLS handshake ناموفق بود: {1}",
    "Direct queries to public resolvers succeeded: {}": "پرس‌وجوی مستقیم به resolverهای عمومی موفق بود: {1}",
    "Largest packet that passed: {} bytes.": "بزرگ‌ترین بسته‌ای که عبور کرد: {1} بایت.",
    "Smallest packet that failed: {} bytes.": "کوچک‌ترین بسته‌ای که رد شد: {1} بایت.",
    "PPPoE, VPN or other encapsulation overhead": "سربار PPPoE، VPN یا کپسوله‌سازی‌های دیگر",
    "A PMTUD problem (ICMP 'fragmentation needed' filtered)": "مشکل PMTUD (پیام ICMP «fragmentation needed» فیلتر شده)",
    "Not a root cause by itself; a reduced MTU is common and often harmless.":
        "به‌تنهایی علت اصلی نیست؛ MTU کاهش‌یافته رایج است و اغلب بی‌ضرر.",
    "Detection is evidence about the environment, not a fault.": "شناسایی، شاهدی درباره‌ی محیط است نه یک عیب.",
    "Site-specific blocking or filtering": "مسدودسازی یا فیلترینگ مخصوص سایت",
    "The site itself is down or rate-limiting": "خود سایت از کار افتاده یا محدودیت نرخ اعمال می‌کند",
    "A single failing site is weak evidence.": "ناموفق بودن فقط یک سایت شاهد ضعیفی است.",
    "Control sites that work": "سایت‌های شاهدی که کار می‌کنند",

    # ------------------------------------------------ probes / graph / runner / icmp
    "Could not resolve {}: {}": "{1} تبدیل به آدرس نشد: {2}",
    "System resolver returned {} for {}": "resolver سیستم برای {2} این را برگرداند: {1}",
    "TCP handshake to {}:{} completed in {} ms": "TCP handshake با {1}:{2} در {3} میلی‌ثانیه کامل شد",
    "Other ports on the same address answered, so the host is up.":
        "پورت‌های دیگر همین آدرس پاسخ دادند، پس میزبان بالاست.",
    "The test could not be completed ({}).": "آزمون کامل نشد ({1}).",
    "Unknown module.": "ماژول ناشناخته.",
    "The system ping command is not available, so ICMP could not be tested.":
        "دستور ping سیستم در دسترس نیست، پس ICMP آزمایش نشد.",
    "{} of {} echo replies received": "{1} از {2} پاسخ echo دریافت شد",
    "An ICMP error was returned{}": "یک پیام خطای ICMP برگشت{1}",
    "0 of {} echo replies received and no ICMP error": "0 از {1} پاسخ echo دریافت شد و هیچ خطای ICMP نیامد",
    "Not run: an earlier step it depends on did not succeed.": "اجرا نشد: مرحله‌ی قبلیِ مورد نیاز آن موفق نبود.",
    "Not run: the diagnostic was cancelled.": "اجرا نشد: عیب‌یابی لغو شد.",
    "Skipped: {} did not succeed, so this test would only repeat that failure.":
        "رد شد: {1} موفق نبود، پس این آزمون فقط همان شکست را تکرار می‌کرد.",
    "Skipped: the diagnostic was cancelled before this test started.": "رد شد: عیب‌یابی پیش از شروع این آزمون لغو شد.",

    # ------------------------------------------------ basic connectivity
    "The server answered HTTP 451 (unavailable for legal reasons).": "سرور پاسخ HTTP 451 (غیرقابل دسترس به دلایل قانونی) داد.",
    "HTTP response {} received from {}": "پاسخ HTTP {1} از {2} دریافت شد",
    "System resolver returned {} address(es) for {}": "resolver سیستم {1} آدرس برای {2} برگرداند",
    "No hops recorded - the route may be filtered.": "هیچ hop ثبت نشد - ممکن است مسیر فیلتر شده باشد.",

    # ------------------------------------------------ DNS
    "{} DNS server(s) configured: {}.": "{1} DNS server تنظیم شده است: {2}.",
    "The configured DNS servers could not be determined on this system.": "DNS serverهای تنظیم‌شده روی این سیستم مشخص نشدند.",
    "{} -> {} via {}": "{1} ← {2} از طریق {3}",
    "{} could not resolve {}: {}": "{1} نتوانست {2} را تبدیل کند: {3}",
    "{} via DoH: {}": "{1} از طریق DoH: {2}",
    "{} ({}): UDP DNS is silent but TCP DNS answers.": "{1} ({2}): DNS روی UDP ساکت است ولی روی TCP پاسخ می‌دهد.",
    "{} ({}): no DNS answer over UDP or TCP.": "{1} ({2}): هیچ پاسخ DNS روی UDP یا TCP نیامد.",
    "The server answered DNS queries ({} of {} resolved)": "سرور به پرس‌وجوهای DNS پاسخ داد ({1} از {2} تبدیل شد)",
    "{} returned {} address(es) for {}": "{1} تعداد {2} آدرس برای {3} برگرداند",
    "{} answered {} for {}": "{1} برای {3} پاسخ {2} داد",
    "{} -> {} via the system resolver": "{1} ← {2} از طریق resolver سیستم",
    "The system resolver could not resolve {} ({}).": "resolver سیستم نتوانست {1} را تبدیل کند ({2}).",
    "Local DNS Configuration": "پیکربندی DNS محلی",
    "UDP/53 query got no answer; TCP/53 query succeeded.": "پرس‌وجوی UDP/53 پاسخی نگرفت؛ پرس‌وجوی TCP/53 موفق بود.",
    "Neither UDP/53 nor TCP/53 produced a DNS answer.": "نه UDP/53 و نه TCP/53 پاسخ DNS نداد.",
    "getaddrinfo({}) failed with {}": "getaddrinfo({1}) با {2} ناموفق شد",
    "{}: could not be tested (internal error).": "{1}: آزمایش نشد (خطای داخلی).",

    # ------------------------------------------------ gateway / local network
    "No usable local network address was found (cable/Wi-Fi disconnected?).":
        "آدرس شبکه‌ی محلی قابل استفاده‌ای پیدا نشد (کابل/Wi-Fi قطع است؟).",
    "The gateway {} answers ping ({} ms).": "gateway ‏{1} به ping پاسخ می‌دهد ({2} میلی‌ثانیه).",
    "The gateway {} answers with packet loss ({}%).": "gateway ‏{1} با از دست رفتن بسته پاسخ می‌دهد ({2}٪).",
    "The gateway {} does not answer ping but responds on TCP ({}).": "gateway ‏{1} به ping پاسخ نمی‌دهد ولی روی TCP پاسخ می‌دهد ({2}).",
    "The gateway {} did not answer ping or TCP probes. Many routers ignore both, so this is only a hint of a local network problem.":
        "gateway ‏{1} به ping و آزمون‌های TCP پاسخ نداد. بسیاری از روترها هر دو را نادیده می‌گیرند، پس این فقط اشاره‌ای به مشکل شبکه‌ی محلی است.",
    "Source address {} selected by the routing table": "آدرس مبدأ {1} توسط جدول مسیریابی انتخاب شد",
    "The routing table could not select a source address for IPv4 or IPv6.": "جدول مسیریابی نتوانست آدرس مبدأ IPv4 یا IPv6 انتخاب کند.",
    "The default route is on-link (no gateway address), as with a VPN/tunnel adapter.":
        "default route از نوع on-link است (بدون آدرس gateway)، مثل کارت VPN/تونل.",
    "{} echo replies from {}": "{1} پاسخ echo از {2}",
    "TCP port answered: {}": "پورت TCP پاسخ داد: {1}",
    "No ICMP reply and no TCP answer from the gateway.": "نه پاسخ ICMP و نه پاسخ TCP از gateway آمد.",
    "Local Interface": "رابط شبکه‌ی محلی",
    "The default gateway could not be determined on this system.": "default gateway روی این سیستم مشخص نشد.",
    "There is no default route, so no traffic can leave this network.": "default route وجود ندارد، پس هیچ ترافیکی نمی‌تواند از این شبکه خارج شود.",
    "No IPv4 default route in the routing table.": "هیچ default route از نوع IPv4 در جدول مسیریابی نیست.",

    # ------------------------------------------------ HTTP layers
    "Not tested: {} depends on a layer that failed.": "آزمایش نشد: {1} به لایه‌ای وابسته است که ناموفق بود.",
    "Skipped - blocked by the failed {} layer.": "رد شد - به‌خاطر شکست لایه‌ی {1} مسدود شد.",
    "{} resolved to {}.": "{1} به {2} تبدیل شد.",
    "HTTP Layer: DNS": "لایه‌ی HTTP: DNS",
    "HTTP Layer: TCP 443": "لایه‌ی HTTP: TCP 443",
    "HTTP Layer: TLS": "لایه‌ی HTTP: TLS",
    "{} could not be completed (internal error).": "{1} کامل نشد (خطای داخلی).",
    "{} could not be completed ({}).": "{1} کامل نشد ({2}).",

    # ------------------------------------------------ latency / MTU
    "{} ({}): {}/{} replies, avg {} ms, min {}, max {}, jitter {} ms, loss {}%.":
        "{1} ({2}): {3} از {4} پاسخ، میانگین {5} میلی‌ثانیه، حداقل {6}، حداکثر {7}، jitter ‏{8} میلی‌ثانیه، از دست رفتن {9}٪.",
    "{}: no reply to {} ICMP probes and no TCP answer; latency could not be measured.":
        "{1}: به {2} آزمون ICMP پاسخی نیامد و TCP هم جواب نداد؛ تأخیر قابل اندازه‌گیری نبود.",
    "{} of {} probes answered over {}": "{1} از {2} آزمون روی {3} پاسخ داد",
    "{}: latency could not be measured (internal error).": "{1}: تأخیر اندازه‌گیری نشد (خطای داخلی).",
    "No reply even at {} bytes, so the path MTU could not be measured (ICMP may be blocked on this path).":
        "حتی با {1} بایت پاسخی نیامد، پس MTU مسیر اندازه‌گیری نشد (ممکن است ICMP در این مسیر مسدود باشد).",
    "Largest DF packet that passed: {} bytes.": "بزرگ‌ترین بسته‌ی DF که عبور کرد: {1} بایت.",
    "Path MTU is {} bytes (standard Ethernet).": "MTU مسیر {1} بایت است (Ethernet استاندارد).",
    "Path MTU is {} bytes, below the standard {}. Possible PPPoE/VPN/encapsulation overhead or a PMTUD problem; this alone does not identify a cause.":
        "MTU مسیر {1} بایت است، کمتر از مقدار استاندارد {2}. ممکن است سربار PPPoE/VPN/کپسوله‌سازی یا مشکل PMTUD باشد؛ این به‌تنهایی علت را مشخص نمی‌کند.",
    "The interface MTU is {}, the path MTU {}: a device on the path limits packet size.":
        "MTU رابط {1} و MTU مسیر {2} است: دستگاهی در مسیر اندازه‌ی بسته را محدود می‌کند.",
    "{} reported that the oversized packet needs fragmentation.": "{1} اعلام کرد که بسته‌ی بزرگ‌تر از حد نیاز به fragmentation دارد.",
    "The MTU could not be measured (internal error).": "MTU اندازه‌گیری نشد (خطای داخلی).",

    # ------------------------------------------------ protocol tests
    "ICMP echo replies received - ICMP is not blocked on this path.": "پاسخ‌های ICMP echo دریافت شد - ICMP در این مسیر مسدود نیست.",
    "UDP/443 could not be probed: {}.": "UDP/443 آزمایش نشد: {1}.",
    "DoH request failed ({}).": "درخواست DoH ناموفق بود ({1}).",
    "DoT failed ({}).": "DoT ناموفق بود ({1}).",
    "WebSocket handshake failed ({}).": "handshake مربوط به WebSocket ناموفق بود ({1}).",
    "Received a UDP response on port 443.": "یک پاسخ UDP روی پورت 443 دریافت شد.",
    "{} could not be completed.": "{1} کامل نشد.",
    "A UDP datagram came back from port 443": "یک datagram ‏UDP از پورت 443 برگشت",
    "No UDP/443 reply. A QUIC server ignores malformed packets, so this alone does not show that QUIC is blocked (see the HTTP/3 test).":
        "پاسخی از UDP/443 نیامد. سرور QUIC بسته‌های ناقص را نادیده می‌گیرد، پس این به‌تنهایی نشان نمی‌دهد QUIC مسدود است (آزمون HTTP/3 را ببینید).",
    "UDP/443 was rejected with an ICMP port-unreachable message.": "UDP/443 با پیام ICMP port-unreachable رد شد.",
    "No reply and no ICMP error within the timeout": "در مهلت تعیین‌شده نه پاسخی آمد و نه خطای ICMP",
    "ICMP port unreachable was reported for UDP/443": "برای UDP/443 پیام ICMP port unreachable گزارش شد",
    "control port: {}; monitored port: {}": "پورت شاهد: {1}؛ پورت تحت نظر: {2}",
    "Control request {}; {} of {} bytes received": "درخواست شاهد {1}؛ {2} از {3} بایت دریافت شد",
    "This check could not be completed.": "این بررسی کامل نشد.",

    # ------------------------------------------------ site reachability
    "HTTPS answered with status {}.": "HTTPS با وضعیت {1} پاسخ داد.",
    "Only private/loopback addresses were returned ({}).": "فقط آدرس‌های خصوصی/loopback برگردانده شد ({1}).",
    "{}: internal error while testing.": "{1}: خطای داخلی در حین آزمایش.",
    "{}: DNS lookup failed ({}).": "{1}: جست‌وجوی DNS ناموفق بود ({2}).",

    # ------------------------------------------------ TCP scanner / TLS
    "Port {} could not be tested (internal error).": "پورت {1} آزمایش نشد (خطای داخلی).",
    "DNS {}": "DNS {1}",
    "{}: the TCP connection to port {} failed ({}); TLS could not start.":
        "{1}: اتصال TCP به پورت {2} ناموفق بود ({3})؛ TLS نتوانست شروع شود.",
    "{}: TLS {} handshake completed in {} ms.": "{1}: handshake ‏TLS ‏{2} در {3} میلی‌ثانیه کامل شد.",
    "{}: DNS resolution failed, the TLS test could not start.": "{1}: تبدیل DNS ناموفق بود، آزمون TLS نتوانست شروع شود.",
    "TCP connect to {}:{} ended with {}": "اتصال TCP به {1}:{2} با {3} پایان یافت",
    "Handshake completed ({}, {})": "handshake کامل شد ({1}، {2})",
    "Certificate problem: {}": "مشکل گواهی: {1}",
    "Handshake with {}: {}": "handshake با {1}: {2}",
    "TCP/{} succeeded, then the TLS phase failed with {}": "TCP/{1} موفق بود، سپس مرحله‌ی TLS با {2} ناموفق شد",
    "{}: the TLS test could not be completed.": "{1}: آزمون TLS کامل نشد.",
    "TLS {} Handshake ({})": "TLS {1} Handshake ‏({2})",

    # ------------------------------------------------ UDP
    "UDP {}: a reply of {} bytes arrived in {} ms.": "UDP {1}: پاسخی به اندازه‌ی {2} بایت در {3} میلی‌ثانیه رسید.",
    "UDP {}: something replied, but not with a valid {} answer.": "UDP {1}: چیزی پاسخ داد، اما پاسخ معتبر {2} نبود.",
    "UDP {}: no reply to a real {} request within {} s; the packet or the reply may have been dropped.":
        "UDP {1}: در {3} ثانیه پاسخی به یک درخواست واقعی {2} نیامد؛ ممکن است بسته یا پاسخ حذف شده باشد.",
    "UDP {}: no reply, which is inconclusive - this tool has no valid {} exchange, so silence proves nothing.":
        "UDP {1}: پاسخی نیامد که نتیجه‌ی قطعی نیست - این ابزار تبادل معتبر {2} ندارد، پس سکوت چیزی را ثابت نمی‌کند.",
    "No datagram and no ICMP error were received.": "نه datagram ای رسید و نه خطای ICMP.",
    "UDP {}: ICMP port unreachable - the host is reachable but nothing listens here.":
        "UDP {1}: ICMP port unreachable - میزبان در دسترس است ولی چیزی روی این پورت گوش نمی‌دهد.",
    "Received {} bytes from {}:{}": "{1} بایت از {2}:{3} دریافت شد",
    "The OS reported an ICMP port-unreachable message for this socket.": "سیستم‌عامل برای این socket پیام ICMP port-unreachable گزارش کرد.",
    "UDP {}: {}.": "UDP {1}: {2}.",
    "UDP {}: socket error ({}).": "UDP {1}: خطای socket ‏({2}).",

    # ------------------------------------------------ VPN connectivity
    "Some VPN transport ports are reachable. This says nothing about whether a specific VPN service works.":
        "برخی پورت‌های انتقال VPN در دسترس‌اند. این چیزی درباره‌ی کار کردن یک سرویس VPN مشخص نمی‌گوید.",
    "No VPN transport port answered. That is not enough to conclude that VPNs are blocked: silence has several ordinary explanations.":
        "هیچ پورت انتقال VPN پاسخ نداد. این برای نتیجه‌گیری درباره‌ی مسدود بودن VPN کافی نیست: سکوت چند توضیح عادی دارد.",
    "{} TCP transport port(s) reachable; TCP-based tunnels are not generally blocked.":
        "{1} پورت انتقال TCP در دسترس است؛ تونل‌های مبتنی بر TCP به‌طور کلی مسدود نیستند.",
    "{} UDP port(s) gave no answer; with no VPN server there this is expected.":
        "{1} پورت UDP پاسخی نداد؛ وقتی آنجا سرور VPN نیست این طبیعی است.",
    "Reading of the results": "برداشت از نتایج",
}
