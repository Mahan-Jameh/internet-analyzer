"""
i18n_fa.py
==========
Persian (Farsi) translation data. Pure data, no logic.

* ``UI_FA``       - fixed interface strings (buttons, labels, dialogs), keyed by
                    the exact English text used in the code.
* ``STATUS_FA``   - status / state words shown in badges and tables.
* ``DYNAMIC_FA``  - templates for the messages produced by the test modules and
                    the analyzer. ``{}`` in a key stands for a value that varies
                    (host name, number, error text ...). The Persian value refers
                    to those values as ``{1}``, ``{2}`` ... in order of appearance.

Technical terms (DNS, TLS, TCP, SNI, QUIC ...) are kept in Latin letters, which is
how Persian-speaking network engineers write them.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Fixed interface strings
# --------------------------------------------------------------------------- #
UI_FA: dict[str, str] = {
    # window / menus / tabs
    "Internet Connectivity & Protocol Analyzer": "تحلیلگر اتصال اینترنت و پروتکل‌ها",
    "Home": "خانه",
    "Diagnostics": "عیب‌یابی",
    "Advanced": "پیشرفته",
    "History": "تاریخچه",
    "Logs": "گزارش‌های لاگ",
    "&File": "پرونده",
    "Export Current Report...": "خروجی گرفتن از گزارش فعلی...",
    "Exit": "خروج",
    "&Language": "زبان",
    "&Help": "راهنما",
    "About": "درباره",
    "Language": "زبان",
    "Please stop or wait for the running diagnostic to finish before changing the language.":
        "لطفاً پیش از تغییر زبان، عیب‌یابیِ در حال اجرا را متوقف کنید یا منتظر پایان آن بمانید.",
    "No Report Yet": "هنوز گزارشی وجود ندارد",
    "Run a diagnostic first before exporting a report.":
        "ابتدا یک عیب‌یابی اجرا کنید، سپس از گزارش خروجی بگیرید.",
    "Version": "نسخه",
    "A diagnostic tool for ordinary users to understand Internet connectivity, protocol support, "
    "and possible network restrictions on their own machine.\n\n"
    "This tool only diagnoses - it never attempts to bypass any restriction.":
        "ابزاری برای کاربران عادی تا اتصال اینترنت، پشتیبانی از پروتکل‌ها و محدودیت‌های احتمالیِ "
        "شبکه را روی دستگاه خودشان بفهمند.\n\n"
        "این ابزار فقط عیب‌یابی می‌کند و هیچ‌گاه تلاشی برای دور زدن محدودیت‌ها نمی‌کند.",
    "OK": "تأیید",
    "Cancel": "انصراف",
    "Yes": "بله",
    "No": "خیر",

    # home
    "Network Overview": "نمای کلی شبکه",
    "Refresh": "به‌روزرسانی",
    "Refreshing...": "در حال به‌روزرسانی...",
    "This is a snapshot of your current network environment. "
    "Run the Diagnostics tab for a full set of tests.":
        "این تصویری لحظه‌ای از شبکه‌ی فعلی شماست. برای مجموعه‌ی کامل آزمون‌ها به تب «عیب‌یابی» بروید.",
    "Loading...": "در حال بارگذاری...",
    "Internet Status": "وضعیت اینترنت",
    "Public IP": "آی‌پی عمومی",
    "ISP": "ارائه‌دهنده‌ی اینترنت",
    "Country": "کشور",
    "City": "شهر",
    "IPv4 Available": "IPv4 در دسترس",
    "IPv6 Available": "IPv6 در دسترس",
    "DNS Servers": "سرورهای DNS",
    "Network Adapter": "کارت شبکه",
    "Gateway": "دروازه (Gateway)",
    "Connected": "متصل",
    "Not Connected": "قطع",
    "N/A": "نامشخص",

    # logs
    "Detailed Logs": "لاگ‌های تفصیلی",
    "Save Log As...": "ذخیره‌ی لاگ...",
    "Log files are also automatically saved to: {}": "فایل‌های لاگ به‌طور خودکار در این مسیر هم ذخیره می‌شوند: {1}",
    "Save Log": "ذخیره‌ی لاگ",
    "Text Files (*.txt)": "پرونده‌های متنی (*.txt)",
    "Saved": "ذخیره شد",
    "Log saved to:\n{}": "لاگ ذخیره شد در:\n{1}",
    "Save Failed": "ذخیره ناموفق بود",
    "Could not save log: {}": "ذخیره‌ی لاگ ممکن نشد: {1}",

    # export dialog
    "Export Report": "خروجی گرفتن از گزارش",
    "Select the format(s) to export:": "قالب(های) خروجی را انتخاب کنید:",
    "Plain Text (.txt)": "متن ساده (.txt)",
    "JSON (.json)": "JSON (.json)",
    "CSV (.csv)": "CSV (.csv)",
    "HTML Report (.html)": "گزارش HTML (.html)",
    "Destination folder:": "پوشه‌ی مقصد:",
    "Browse...": "انتخاب...",
    "Choose Destination Folder": "انتخاب پوشه‌ی مقصد",
    "No Format Selected": "قالبی انتخاب نشده",
    "Please select at least one export format.": "لطفاً دست‌کم یک قالب خروجی انتخاب کنید.",
    "Export Failed": "خروجی گرفتن ناموفق بود",
    "Could not export report: {}": "خروجی گرفتن از گزارش ممکن نشد: {1}",
    "Export Complete": "خروجی آماده شد",
    "Saved:\n": "ذخیره شد:\n",

    # diagnostics tab
    "Run Diagnostic": "اجرای عیب‌یابی",
    "Stop": "توقف",
    "Export Report...": "خروجی گزارش...",
    "Tests to run": "آزمون‌های مورد اجرا",
    "(optional)": "(اختیاری)",
    "May briefly interrupt your connection (a filter can drop your packets for about a minute "
    "after seeing unusual traffic). You will be asked to confirm.":
        "ممکن است اتصال شما را برای مدتی کوتاه مختل کند (یک فیلتر می‌تواند پس از دیدن ترافیک غیرعادی "
        "حدود یک دقیقه بسته‌های شما را حذف کند). پیش از اجرا از شما تأیید گرفته می‌شود.",
    "Select all": "انتخاب همه",
    "Default selection": "انتخاب پیش‌فرض",
    "Repeat": "تکرار",
    " time(s)": " بار",
    "every": "هر",
    " s": " ثانیه",
    "Ready. Click \"Run Diagnostic\" to begin.": "آماده. برای شروع روی «اجرای عیب‌یابی» بزنید.",
    "Select at least one test to run.": "دست‌کم یک آزمون برای اجرا انتخاب کنید.",
    "Optional test may interrupt your connection": "آزمون اختیاری ممکن است اتصال شما را مختل کند",
    "The Protocol Whitelist Probe sends unusual traffic on purpose. A network filter that reacts "
    "to it may drop your packets for about a minute, so websites may stop loading briefly.\n\n"
    "Run it anyway?":
        "آزمون «Protocol Whitelist» عمداً ترافیک غیرعادی می‌فرستد. اگر یک فیلتر شبکه به آن واکنش "
        "نشان دهد، ممکن است حدود یک دقیقه بسته‌های شما را حذف کند و وب‌سایت‌ها برای مدتی باز نشوند.\n\n"
        "با این حال اجرا شود؟",
    "WAITING": "در انتظار",
    "RUNNING": "در حال اجرا",
    "NOT TESTED": "آزموده نشده",
    "Run {} of {}: ": "اجرای {1} از {2}: ",
    "Starting diagnostics...": "در حال شروع عیب‌یابی...",
    "Stopping after the current test finishes...": "پس از پایان آزمون جاری متوقف می‌شود...",
    "Repeat series stopped.": "تکرارها متوقف شد.",
    "Run {} of {} finished. Next run in {} s (press Stop to cancel).":
        "اجرای {1} از {2} تمام شد. اجرای بعدی تا {3} ثانیه دیگر (برای لغو، «توقف» را بزنید).",
    "Run cancelled.": "اجرا لغو شد.",
    "All tests completed.": "همه‌ی آزمون‌ها انجام شد.",
    " Took {} s.": " زمان اجرا: {1} ثانیه.",
    "The run could not be completed: {}": "اجرا کامل نشد: {1}",
    "Analysis Summary": "خلاصه‌ی تحلیل",
    "These are probabilistic interpretations based on the observed results - "
    "not definitive claims about censorship or network policy.":
        "این‌ها تفسیرهای احتمالی بر پایه‌ی نتایج مشاهده‌شده‌اند، نه ادعای قطعی درباره‌ی سانسور یا سیاست شبکه.",

    # advanced tab
    "Advanced Mode": "حالت پیشرفته",
    "Choose a custom target host and specific ports to test. Port selection is restricted "
    "to a fixed set of well known ports for safety.":
        "یک میزبان هدف دلخواه و پورت‌های مشخص را برای آزمون انتخاب کنید. برای ایمنی، انتخاب پورت "
        "فقط به مجموعه‌ای ثابت از پورت‌های شناخته‌شده محدود است.",
    "Target Host": "میزبان هدف",
    "e.g. 1.1.1.1 or example.com (leave empty for defaults)":
        "مثلاً 1.1.1.1 یا example.com (برای حالت پیش‌فرض خالی بگذارید)",
    "TCP Ports": "پورت‌های TCP",
    "UDP Ports": "پورت‌های UDP",
    "Websites to test (one per line, up to {})": "وب‌سایت‌های مورد آزمون (هر خط یکی، حداکثر {1})",
    "example.com\nanother-site.org\n(leave empty to use the built-in list of popular services)":
        "example.com\nanother-site.org\n(برای استفاده از فهرست پیش‌فرضِ سرویس‌های پرکاربرد خالی بگذارید)",
    "Profiles": "پروفایل‌ها",
    "Load": "بارگذاری",
    "Save Current As...": "ذخیره‌ی تنظیمات فعلی...",
    "Delete": "حذف",
    "Run With These Settings": "اجرا با این تنظیمات",
    "Invalid Target": "هدف نامعتبر",
    "The target must be a host name (example.com) or an IP address, without spaces or a leading '-'.":
        "هدف باید نام میزبان (example.com) یا آدرس آی‌پی باشد، بدون فاصله و بدون «-» در ابتدا.",
    "Some entries ignored": "برخی ورودی‌ها نادیده گرفته شد",
    "{} line(s) were not valid domain names or were duplicates, and will be skipped.":
        "{1} خط نام دامنه‌ی معتبر نبود یا تکراری بود و نادیده گرفته می‌شود.",
    "Save Profile": "ذخیره‌ی پروفایل",
    "Profile name:": "نام پروفایل:",
    "Invalid Name": "نام نامعتبر",
    "Please use a valid profile name.": "لطفاً نام معتبری برای پروفایل بگذارید.",
    "Could not save profile: {}": "ذخیره‌ی پروفایل ممکن نشد: {1}",
    "No Profile": "پروفایلی نیست",
    "There are no saved profiles yet.": "هنوز پروفایلی ذخیره نشده است.",
    "Load Failed": "بارگذاری ناموفق بود",
    "Could not load profile: {}": "بارگذاری پروفایل ممکن نشد: {1}",
    "Delete Profile": "حذف پروفایل",
    "Delete profile '{}'? This cannot be undone.": "پروفایل «{1}» حذف شود؟ این کار بازگشت‌پذیر نیست.",
    "Delete Failed": "حذف ناموفق بود",
    "Could not delete profile: {}": "حذف پروفایل ممکن نشد: {1}",

    # history tab
    "History & Comparison": "تاریخچه و مقایسه",
    "Every completed run is saved automatically. Pick two runs to see what changed between them.":
        "هر اجرای کامل‌شده خودکار ذخیره می‌شود. دو اجرا را انتخاب کنید تا تفاوت‌ها را ببینید.",
    "Earlier run:": "اجرای قدیمی‌تر:",
    "Later run:": "اجرای جدیدتر:",
    "Compare Selected": "مقایسه‌ی انتخاب‌شده‌ها",
    "Compare Latest Two": "مقایسه‌ی دو اجرای اخیر",
    "Refresh List": "به‌روزرسانی فهرست",
    "Module": "ماژول",
    "Check": "بررسی",
    "Earlier": "قدیمی‌تر",
    "Later": "جدیدتر",
    "Change": "تغییر",
    "At least two saved runs are needed. Run the diagnostics twice to compare.":
        "دست‌کم دو اجرای ذخیره‌شده لازم است. برای مقایسه، عیب‌یابی را دو بار اجرا کنید.",
    "Same run": "اجرای یکسان",
    "Please choose two different runs.": "لطفاً دو اجرای متفاوت انتخاب کنید.",
    "Could not open report": "باز کردن گزارش ممکن نشد",
    "<b>{}</b> improved, <b>{}</b> got worse, <b>{}</b> other change(s), <b>{}</b> unchanged.":
        "<b>{1}</b> مورد بهتر شد، <b>{2}</b> مورد بدتر شد، <b>{3}</b> تغییر دیگر، <b>{4}</b> مورد بدون تغییر.",
    "Network environment changed:\n": "محیط شبکه تغییر کرده است:\n",
    "Network environment: no changes.": "محیط شبکه: بدون تغییر.",
    "Earlier: {}\nLater: {}": "قدیمی‌تر: {1}\nجدیدتر: {2}",
}

# --------------------------------------------------------------------------- #
# Status, state and change words
# --------------------------------------------------------------------------- #
STATUS_FA: dict[str, str] = {
    "OK": "سالم",
    "WARNING": "هشدار",
    "FAILED": "ناموفق",
    "UNKNOWN": "نامشخص",
    "WAITING": "در انتظار",
    "RUNNING": "در حال اجرا",
    "NOT TESTED": "آزموده نشده",
    # port / probe states
    "OPEN": "باز", "CLOSED": "بسته", "FILTERED": "فیلترشده", "TIMEOUT": "بدون پاسخ", "RESET": "ریست‌شده",
    "open": "باز", "closed": "بسته", "filtered": "فیلترشده", "timeout": "بدون پاسخ", "reset": "ریست‌شده",
    # comparison results
    "improved": "بهتر شد", "degraded": "بدتر شد", "changed": "تغییر کرد",
    "new": "جدید", "removed": "حذف‌شده",
    "IMPROVED": "بهتر شد", "DEGRADED": "بدتر شد", "CHANGED": "تغییر کرد",
    "NEW": "جدید", "REMOVED": "حذف‌شده",
}

# Single words / short phrases that appear inside larger messages.
WORDS_FA: dict[str, str] = {
    "control": "کنترل",
    "test": "آزمون",
    "N/A": "نامشخص",
    "Cloudflare": "Cloudflare",
    "Custom target": "هدف دلخواه",
    "Yes": "بله",
    "No": "خیر",
    "True": "بله",
    "False": "خیر",
    # network field labels used by the report comparison
    "Public IP": "آی‌پی عمومی",
    "ISP": "ارائه‌دهنده‌ی اینترنت",
    "Country": "کشور",
    "City": "شهر",
    "IPv4 available": "IPv4 در دسترس",
    "IPv6 available": "IPv6 در دسترس",
    "DNS servers": "سرورهای DNS",
    "Network adapter": "کارت شبکه",
    "Gateway": "دروازه (Gateway)",
    "Internet reachable": "اتصال اینترنت",
    # module / check names
    "Network Information": "اطلاعات شبکه",
    "Proxy & VPN Detection": "تشخیص پروکسی و VPN",
    "Basic Connectivity": "اتصال پایه",
    "DNS Test": "آزمون DNS",
    "TCP Port Scanner": "اسکن پورت TCP",
    "UDP Test": "آزمون UDP",
    "TLS Test": "آزمون TLS",
    "HTTP Test": "آزمون HTTP",
    "TCP Stall Test": "آزمون توقف TCP",
    "Website Reachability": "دسترس‌پذیری وب‌سایت‌ها",
    "Protocol Tests": "آزمون پروتکل‌ها",
    "Latency Test": "آزمون تأخیر",
    "MTU Test": "آزمون MTU",
    "VPN-Related Connectivity": "اتصال مرتبط با VPN",
    "Protocol Whitelist Probe": "پروب Protocol Whitelist",
    "HTTP Request": "درخواست HTTP",
    "HTTPS Request": "درخواست HTTPS",
    "Plain HTTP": "HTTP ساده",
    "HTTPS": "HTTPS",
    "HTTP/2 Support": "پشتیبانی از HTTP/2",
    "HTTP/3 (QUIC) Support": "پشتیبانی از HTTP/3 (QUIC)",
    "HTTP Redirect": "تغییر مسیر HTTP",
    "Response Compression": "فشرده‌سازی پاسخ",
    "Connection Reuse (Keep-Alive)": "استفاده‌ی مجدد از اتصال (Keep-Alive)",
    "Block Page Detection": "تشخیص صفحه‌ی مسدودسازی",
    "Block Page": "صفحه‌ی مسدودسازی",
    "DNS Answer Comparison": "مقایسه‌ی پاسخ‌های DNS",
    "Resolve via system DNS (OS default)": "حل نام با DNS سیستم (پیش‌فرض ویندوز)",
    "Resolve via DNS-over-HTTPS (Cloudflare)": "حل نام با DNS-over-HTTPS (Cloudflare)",
    "Path MTU Discovery": "کشف MTU مسیر",
    "SNI Filtering Probe": "پروب فیلترینگ SNI",
    "Certificate Validation": "اعتبارسنجی گواهی",
    "Control vs Test Comparison": "مقایسه‌ی سایت‌های کنترل و آزمون",
    "System Proxy Settings": "تنظیمات پروکسی سیستم",
    "Local Proxy Listeners": "برنامه‌های شنوده‌ی پروکسی محلی",
    "VPN / Tunnel Adapters": "کارت‌های VPN / تونل",
    "QUIC Transport Reachability": "دسترس‌پذیری لایه‌ی QUIC",
    "ICMP Echo": "ICMP Echo (پینگ)",
    "WebSocket (wss://)": "WebSocket (wss://)",
    "Scope Notice": "توجه درباره‌ی دامنه‌ی آزمون",
    "Protocol Whitelist": "Protocol Whitelist",
    "TCP Stall (16-20 KB) Test": "آزمون توقف TCP (۱۶ تا ۲۰ کیلوبایت)",
    "TCP Stall": "توقف TCP",
    "Control vs Test": "کنترل در برابر آزمون",
    "TLS 1.3": "TLS 1.3",
    "TLS 1.2": "TLS 1.2",
    "TCP 443": "TCP 443",
    "UDP 443": "UDP 443",
    "Cloudflare DoH": "Cloudflare DoH",
    # reasons inside the block page message
    "HTTP 451 (unavailable for legal reasons)": "HTTP 451 (غیرقابل‌دسترس به دلایل قانونی)",
    "page embeds an iframe from a private address": "صفحه یک iframe از یک آدرس خصوصی را در خود جاسازی کرده است",
    # reasons inside the website reachability message
    "no answer (packets may be dropped)": "بدون پاسخ (ممکن است بسته‌ها حذف شده باشند)",
    "the connection was reset": "اتصال ریست شد",
    "the connection was refused": "اتصال رد شد",
    "the network reported the address as unreachable": "شبکه آدرس را غیرقابل‌دسترس اعلام کرد",
    "name resolution (the DNS answer was missing or looked tampered with)":
        "حل نام (پاسخ DNS وجود نداشت یا دست‌کاری‌شده به نظر می‌رسید)",
    "the TCP connection (packets dropped or reset before any handshake)":
        "اتصال TCP (بسته‌ها پیش از هر دست‌دهی حذف یا ریست شدند)",
    "the TLS handshake (TCP worked, but the encrypted handshake was cut - consistent with the network looking at the site name)":
        "دست‌دهی TLS (TCP کار کرد اما دست‌دهی رمزنگاری‌شده قطع شد؛ سازگار با بررسی نام سایت توسط شبکه)",
    "the HTTPS request (a block page or error status)": "درخواست HTTPS (صفحه‌ی مسدودسازی یا وضعیت خطا)",
}

# --------------------------------------------------------------------------- #
# Messages produced by the tests and by the analyzer
# --------------------------------------------------------------------------- #
DYNAMIC_FA: dict[str, str] = {
    # ------------------------------------------------------------ analyzer
    "No notable issues were detected in this run.": "در این اجرا مشکل قابل‌توجهی دیده نشد.",
    "Internet connectivity is available on this machine.": "اتصال اینترنت روی این دستگاه برقرار است.",
    "No Internet connectivity could be confirmed at all. Check your cable/Wi-Fi, router, and modem before investigating anything else.":
        "هیچ اتصال اینترنتی تأیید نشد. پیش از بررسی هر چیز دیگر، کابل/Wi-Fi، روتر و مودم را بررسی کنید.",
    "One or more DNS resolvers returned a known block-page style address. This strongly suggests DNS-based filtering or DNS poisoning is affecting this network.":
        "یک یا چند DNS resolver آدرسی شبیه صفحه‌ی مسدودسازی برگرداندند. این موضوع قویاً نشان می‌دهد "
        "فیلترینگ مبتنی بر DNS یا مسموم‌سازی DNS (DNS poisoning) روی این شبکه اثر دارد.",
    "Different public DNS resolvers returned inconsistent results for well known domains. This could indicate DNS interference, but may also be normal CDN behaviour - treat as a possible signal, not proof.":
        "DNS resolverهای عمومیِ مختلف برای دامنه‌های شناخته‌شده نتایج ناهمخوان برگرداندند. این می‌تواند "
        "نشانه‌ی دخالت در DNS باشد، اما رفتار عادی CDN هم می‌تواند باشد؛ آن را نشانه‌ای احتمالی بدانید، نه مدرک.",
    "The following DNS resolvers could not be reached at all: {}. The network may be blocking outbound DNS queries to non-default servers.":
        "به این DNS resolverها اصلاً دسترسی پیدا نشد: {1}. ممکن است شبکه پرس‌وجوهای DNS به سرورهای غیرپیش‌فرض را مسدود کرده باشد.",
    "TCP port 443 (standard HTTPS) does not appear reachable in the port scan. This may indicate that HTTPS traffic is being blocked on this network.":
        "در اسکن پورت، پورت TCP 443 (HTTPS استاندارد) در دسترس به نظر نمی‌رسد. ممکن است ترافیک HTTPS روی این شبکه مسدود شده باشد.",
    "Connections to {} were actively reset rather than timing out. An active reset (rather than silence) often indicates a firewall or middlebox is specifically intercepting this traffic, rather than a simple routing failure.":
        "اتصال به {1} به‌جای بی‌پاسخ ماندن، به‌طور فعال ریست شد. ریست فعال (به‌جای سکوت) معمولاً نشان می‌دهد "
        "یک فایروال یا دستگاه میانی عمداً این ترافیک را قطع می‌کند و صرفاً مشکل مسیریابی نیست.",
    "UDP port 443 (used by QUIC / HTTP-3) appears actively blocked (ICMP rejection received). The network may restrict UDP-based protocols.":
        "پورت UDP 443 (مورد استفاده‌ی QUIC / HTTP-3) به‌طور فعال مسدود به نظر می‌رسد (رد ICMP دریافت شد). "
        "ممکن است شبکه پروتکل‌های مبتنی بر UDP را محدود کرده باشد.",
    "TLS 1.3 handshakes failed while TLS 1.2 succeeded. Some filtering systems specifically target newer TLS versions or ClientHello fingerprints - this pattern can be a sign of that, though it may also be an unrelated server issue.":
        "دست‌دهی TLS 1.3 ناموفق بود ولی TLS 1.2 موفق شد. برخی سامانه‌های فیلترینگ نسخه‌های جدیدتر TLS یا "
        "اثرانگشت ClientHello را هدف می‌گیرند؛ این الگو می‌تواند نشانه‌ی آن باشد، هرچند ممکن است مشکلی نامرتبط در سرور باشد.",
    "TLS handshakes failed for both TLS 1.2 and TLS 1.3 to the same host(s). This suggests a broader TLS/HTTPS connectivity problem rather than version-specific filtering.":
        "دست‌دهی TLS هم برای 1.2 و هم برای 1.3 با همان میزبان(ها) ناموفق بود. این بیشتر به مشکلی گسترده‌تر در اتصال "
        "TLS/HTTPS اشاره دارد تا فیلترینگِ مخصوص یک نسخه.",
    "Certificate validation could not be completed for one or more hosts. This can happen with interception proxies (including some antivirus/firewall software), captive portals, or genuine connectivity failures.":
        "اعتبارسنجی گواهی برای یک یا چند میزبان کامل نشد. این می‌تواند به دلیل پروکسی‌های شنود (از جمله برخی "
        "آنتی‌ویروس/فایروال‌ها)، صفحه‌های ورود شبکه (captive portal) یا قطعی واقعی اتصال باشد.",
    "HTTP/3 (QUIC) does not appear to be working on this network, even though the target server supports it. UDP-based HTTP/3 traffic may be restricted.":
        "HTTP/3 (QUIC) روی این شبکه کار نمی‌کند، با اینکه سرور هدف از آن پشتیبانی می‌کند. ممکن است ترافیک HTTP/3 مبتنی بر UDP محدود شده باشد.",
    "The server did not negotiate HTTP/2 even though it normally supports it. This can indicate that something on the network path is interfering with the TLS ALPN negotiation.":
        "سرور HTTP/2 را مذاکره نکرد، با اینکه معمولاً از آن پشتیبانی می‌کند. این ممکن است نشان دهد چیزی در مسیر "
        "شبکه در مذاکره‌ی TLS ALPN دخالت می‌کند.",
    "Both DNS-over-HTTPS and DNS-over-TLS failed. The network may be blocking encrypted DNS protocols specifically, forcing reliance on plain-text DNS (which is easier to monitor or filter).":
        "هم DNS-over-HTTPS و هم DNS-over-TLS ناموفق بودند. ممکن است شبکه به‌طور مشخص پروتکل‌های DNS رمزنگاری‌شده را "
        "مسدود کرده باشد و شما را به DNS ساده (که پایش و فیلتر کردنش آسان‌تر است) وابسته کند.",
    "DNS-over-HTTPS failed for the tested provider(s), while other DNS paths may still work. This could indicate targeted blocking of DoH endpoints.":
        "DNS-over-HTTPS برای ارائه‌دهنده(های) آزموده‌شده ناموفق بود، در حالی که مسیرهای دیگر DNS ممکن است کار کنند. "
        "این می‌تواند نشانه‌ی مسدودسازی هدفمند نقاط پایانی DoH باشد.",
    "DNS-over-TLS (port 853) failed for the tested provider(s). Some networks block this specific port since it is exclusively used for encrypted DNS.":
        "DNS-over-TLS (پورت 853) برای ارائه‌دهنده(های) آزموده‌شده ناموفق بود. برخی شبکه‌ها این پورت را مسدود می‌کنند، چون فقط برای DNS رمزنگاری‌شده به کار می‌رود.",
    "ICMP echo (ping) requests are not being answered. This is very commonly a normal firewall configuration and is not by itself a strong censorship signal.":
        "درخواست‌های ICMP echo (پینگ) پاسخ داده نمی‌شوند. این معمولاً پیکربندی عادی فایروال است و به‌تنهایی نشانه‌ی قوی سانسور نیست.",
    "Notably high average latency was measured for: {}. This can be caused by traffic being routed through additional inspection points, or simply by distance/ISP routing - both are possible explanations.":
        "تأخیر میانگین قابل‌توجهی برای این موارد اندازه‌گیری شد: {1}. علت می‌تواند عبور ترافیک از نقاط بازرسی اضافی "
        "یا صرفاً فاصله/مسیریابی ISP باشد؛ هر دو توضیح ممکن‌اند.",
    "Significant packet loss was measured for: {}. This usually points to a congested or unstable link rather than deliberate blocking.":
        "افت بسته‌ی قابل‌توجهی برای این موارد اندازه‌گیری شد: {1}. این معمولاً به خطی شلوغ یا ناپایدار اشاره دارد، نه مسدودسازی عمدی.",
    "The estimated path MTU ({} bytes) is below the standard 1500 bytes. This can cause intermittent failures or slowness for larger packets/connections, particularly with VPNs or tunnelled traffic.":
        "MTU تخمینیِ مسیر ({1} بایت) کمتر از مقدار استاندارد ۱۵۰۰ بایت است. این می‌تواند برای بسته‌ها/اتصال‌های بزرگ‌تر "
        "باعث خطاهای گاه‌به‌گاه یا کندی شود، به‌ویژه با VPN یا ترافیک تونل‌شده.",
    "TLS handshakes to the same server were cut for some website names but not for others. This pattern is consistent with SNI-based filtering, where the network inspects the name in the handshake. It may also have other causes, so treat it as a possibility rather than a conclusion.":
        "دست‌دهی TLS با یک سرور مشخص برای برخی نام‌های وب‌سایت قطع شد ولی برای بقیه نه. این الگو با فیلترینگ مبتنی بر SNI "
        "سازگار است، یعنی شبکه نام داخل دست‌دهی را بررسی می‌کند. ممکن است علت‌های دیگری هم داشته باشد؛ آن را احتمال بدانید، نه نتیجه‌ی قطعی.",
    "No sign of SNI-based filtering: TLS handshakes behaved the same for every name tested.":
        "نشانه‌ای از فیلترینگ مبتنی بر SNI دیده نشد: دست‌دهی TLS برای همه‌ی نام‌های آزموده‌شده یکسان رفتار کرد.",
    "Some TCP ports ({}) time out while others such as {} connect normally. Packets to those ports may be silently dropped by a firewall on this network, although the remote server could also simply not listen there.":
        "برخی پورت‌های TCP ({1}) بی‌پاسخ می‌مانند، در حالی که پورت‌های دیگری مثل {2} عادی وصل می‌شوند. ممکن است فایروالی "
        "روی این شبکه بسته‌های این پورت‌ها را بی‌صدا حذف کند، هرچند ممکن است سرور مقصد هم روی آن‌ها گوش نکند.",
    "Connections to some ports were actively reset while others succeeded, which can indicate a device on the path rejecting that specific traffic.":
        "اتصال به برخی پورت‌ها به‌طور فعال ریست شد و بقیه موفق بودند؛ این می‌تواند نشان دهد دستگاهی در مسیر همان ترافیک مشخص را رد می‌کند.",
    "None of the tested TCP ports connected. This usually means a general connectivity problem or a network that blocks outgoing connections.":
        "به هیچ‌یک از پورت‌های TCP آزموده‌شده وصل نشد. این معمولاً یعنی مشکل عمومی اتصال یا شبکه‌ای که اتصال‌های خروجی را مسدود می‌کند.",
    "A download started normally but stopped after roughly 10-40 KB. Some filtering systems behave this way for certain hosting providers. A weak or unstable connection can look the same, so this is a possibility only.":
        "دانلود عادی شروع شد اما پس از حدود ۱۰ تا ۴۰ کیلوبایت متوقف شد. برخی سامانه‌های فیلترینگ برای بعضی ارائه‌دهندگان "
        "هاستینگ چنین رفتاری دارند. اتصال ضعیف یا ناپایدار هم می‌تواند همین‌طور باشد، پس این فقط یک احتمال است.",
    "Some test websites failed while the control sites worked. The failures happened at: {}. This suggests restrictions specific to those sites, but it cannot prove who or what causes them.":
        "برخی وب‌سایت‌های آزمون ناموفق بودند در حالی که سایت‌های کنترل کار کردند. خطاها در این مرحله رخ دادند: {1}. این به محدودیت‌های "
        "مخصوص همان سایت‌ها اشاره دارد، اما نمی‌تواند ثابت کند علتش چه کسی یا چه چیزی است.",
    "The control websites also failed, so per-site results are not reliable. Fix the general connection first.":
        "سایت‌های کنترل هم ناموفق بودند، پس نتایج تک‌تک سایت‌ها قابل اتکا نیست. ابتدا اتصال عمومی را درست کنید.",
    "The plain HTTP response contained signs of a block page (e.g. status 451 or a redirect to a private address).":
        "پاسخ HTTP ساده نشانه‌هایی از صفحه‌ی مسدودسازی داشت (مثلاً وضعیت 451 یا تغییر مسیر به یک آدرس خصوصی).",
    "TCP connections succeeded but TLS handshakes failed on the same host. That points at the encrypted handshake itself (for example a device inspecting the ClientHello) rather than at the address being unreachable. A server-side or software issue can look the same.":
        "اتصال TCP موفق بود اما دست‌دهی TLS روی همان میزبان ناموفق شد. این به خودِ دست‌دهی رمزنگاری‌شده اشاره دارد "
        "(مثلاً دستگاهی که ClientHello را بررسی می‌کند) و نه به غیرقابل‌دسترس بودن آدرس. مشکل سمت سرور یا نرم‌افزار هم می‌تواند همین‌طور باشد.",
    "A proxy or VPN/tunnel may be active on this computer. If it is, every test here measured that tunnel rather than your direct Internet connection, so the other results should be read with that in mind. Disconnect it and run the diagnostics again to see your real connection.":
        "ممکن است روی این رایانه یک پروکسی یا VPN/تونل فعال باشد. اگر چنین است، همه‌ی آزمون‌ها آن تونل را سنجیده‌اند و نه اتصال "
        "مستقیم شما؛ پس نتایج دیگر را با این در نظر گرفتن بخوانید. آن را قطع کنید و عیب‌یابی را دوباره اجرا کنید تا اتصال واقعی‌تان را ببینید.",
    "Unusual traffic on port 443 got no reaction while the same traffic on another port did. That is the pattern of a filter allowing only recognisable protocols on standard ports. Other explanations exist, so this is a possibility rather than a conclusion.":
        "ترافیک غیرعادی روی پورت 443 واکنشی نگرفت، در حالی که همان ترافیک روی پورت دیگر واکنش گرفت. این الگوی فیلتری است که روی "
        "پورت‌های استاندارد فقط پروتکل‌های قابل‌شناسایی را عبور می‌دهد. توضیح‌های دیگری هم وجود دارد، پس این یک احتمال است نه نتیجه‌ی قطعی.",
    "DNS resolution is working ({} resolver(s) answered all test domains).":
        "حل نام DNS کار می‌کند ({1} resolver به همه‌ی دامنه‌های آزمون پاسخ دادند).",
    "At least one TLS handshake completed successfully.": "دست‌کم یک دست‌دهی TLS با موفقیت کامل شد.",
    "HTTP/2 negotiated successfully.": "HTTP/2 با موفقیت مذاکره شد.",
    "IPv6 connectivity is unavailable on this network. This is common and usually not an issue by itself, since most services still work fine over IPv4.":
        "اتصال IPv6 روی این شبکه در دسترس نیست. این رایج است و معمولاً به‌تنهایی مشکلی نیست، چون بیشتر سرویس‌ها روی IPv4 هم خوب کار می‌کنند.",
    "IPv4 connectivity is unavailable, which is unusual and likely indicates a serious connectivity problem.":
        "اتصال IPv4 در دسترس نیست؛ این غیرعادی است و احتمالاً نشانه‌ی مشکل جدی اتصال است.",

    # ------------------------------------------------- basic connectivity
    "Pinging {} ...": "در حال پینگ {1} ...",
    "Ping {}": "پینگ {1}",
    "No reply received (100% packet loss or ICMP blocked).": "پاسخی دریافت نشد (۱۰۰٪ افت بسته یا ICMP مسدود است).",
    "Partial packet loss: {}% of packets lost.": "افت بسته‌ی جزئی: {1}٪ از بسته‌ها از دست رفت.",
    "Reachable, average RTT {} ms.": "در دسترس، میانگین RTT برابر {1} میلی‌ثانیه.",
    "Tracing route to {} ...": "در حال ردیابی مسیر به {1} ...",
    "Traceroute {}": "ردیابی مسیر {1}",
    "Traceroute could not be executed on this system.": "ردیابی مسیر روی این سیستم اجرا نشد.",
    "No hops recorded - route may be filtered.": "هیچ گامی ثبت نشد؛ ممکن است مسیر فیلتر شده باشد.",
    "Route traced through {} hop(s).": "مسیر از {1} گام عبور کرد.",
    "Resolving {} ...": "در حال حل نام {1} ...",
    "DNS Resolution ({})": "حل نام DNS ({1})",
    "Name could not be resolved.": "نام حل نشد.",
    "Resolved to: {}": "حل شد به: {1}",
    "Requesting {} ...": "در حال درخواست {1} ...",
    "HTTP {} in {} ms.": "HTTP {1} در {2} میلی‌ثانیه.",
    "Server responded with HTTP {}.": "سرور با HTTP {1} پاسخ داد.",
    "Request timed out.": "مهلت درخواست تمام شد.",
    "TLS/SSL error: {}": "خطای TLS/SSL: {1}",
    "Connection failed: {}": "اتصال ناموفق بود: {1}",
    "Request failed: {}": "درخواست ناموفق بود: {1}",

    # ------------------------------------------------------------- DNS
    "Resolve via DNS-over-HTTPS (Cloudflare)": "حل نام با DNS-over-HTTPS (Cloudflare)",
    "DNS-over-HTTPS could not be used, so it is not part of the comparison.":
        "DNS-over-HTTPS قابل استفاده نبود، پس در مقایسه شرکت داده نشد.",
    "{}/{} domains resolved over HTTPS in {} ms.": "{1} از {2} دامنه روی HTTPS در {3} میلی‌ثانیه حل شد.",
    "The system DNS could not resolve any test domain.": "DNS سیستم هیچ‌یک از دامنه‌های آزمون را حل نکرد.",
    "Only {}/{} domains resolved by the system DNS.": "فقط {1} از {2} دامنه توسط DNS سیستم حل شد.",
    "All {} test domains resolved in {} ms.": "هر {1} دامنه‌ی آزمون در {2} میلی‌ثانیه حل شد.",
    "Resolve via {} ({})": "حل نام با {1} ({2})",
    "No domain could be resolved - resolver unreachable or blocked.":
        "هیچ دامنه‌ای حل نشد؛ resolver در دسترس نیست یا مسدود است.",
    "Only {}/{} domains resolved.": "فقط {1} از {2} دامنه حل شد.",
    "Resolver(s) returned a known block-page style address for: {}.":
        "resolver(ها) برای این دامنه‌ها آدرسی شبیه صفحه‌ی مسدودسازی برگرداندند: {1}.",
    "One resolver returned answers sharing nothing with any other resolver for: {}. This can indicate DNS interference, but can also be normal CDN/anycast behaviour.":
        "یک resolver برای این دامنه‌ها پاسخ‌هایی داد که هیچ اشتراکی با resolverهای دیگر نداشت: {1}. این می‌تواند نشانه‌ی دخالت در DNS "
        "باشد، اما رفتار عادی CDN/anycast هم می‌تواند باشد.",
    "No resolver stands out: answers are consistent across resolvers.":
        "هیچ resolverی متفاوت نیست: پاسخ‌ها در همه‌ی resolverها همخوان است.",

    # ------------------------------------------------ environment check
    "Checking for an active proxy or VPN on this computer ...": "در حال بررسی وجود پروکسی یا VPN فعال روی این رایانه ...",
    "system proxy enabled: {}": "پروکسی سیستم فعال است: {1}",
    "proxy auto-config script: {}": "اسکریپت پیکربندی خودکار پروکسی: {1}",
    "environment variable {} is set": "متغیر محیطی {1} تنظیم شده است",
    "A proxy appears to be configured ({}). Test traffic may be going through it instead of your direct connection.":
        "به نظر می‌رسد یک پروکسی تنظیم شده است ({1}). ممکن است ترافیک آزمون به‌جای اتصال مستقیم شما از آن عبور کند.",
    "No system proxy is configured.": "هیچ پروکسی‌ای در سیستم تنظیم نشده است.",
    "Something is listening on common proxy ports of this computer: {}. A proxy or VPN program may be running. Another program can use the same port for something unrelated, so this is only a hint.":
        "چیزی روی پورت‌های رایج پروکسی این رایانه گوش می‌دهد: {1}. ممکن است برنامه‌ی پروکسی یا VPN در حال اجرا باشد. "
        "برنامه‌ی دیگری هم می‌تواند از همین پورت برای کاری نامرتبط استفاده کند، پس این فقط یک اشاره است.",
    "Nothing is listening on the common local proxy ports checked.": "روی پورت‌های رایج پروکسی محلی که بررسی شد، چیزی گوش نمی‌دهد.",
    "The list of network adapters could not be read.": "فهرست کارت‌های شبکه خوانده نشد.",
    "Adapters with VPN/tunnel-like names exist: {}. Having one installed does not mean it is connected, but if it is, results describe the tunnel rather than your direct connection.":
        "کارت‌هایی با نام شبیه VPN/تونل وجود دارند: {1}. نصب بودنِ آن‌ها به معنی متصل بودن نیست، اما اگر متصل باشند نتایج وضعیت تونل را "
        "نشان می‌دهند، نه اتصال مستقیم شما.",
    "No adapters with VPN/tunnel-like names were found.": "کارتی با نام شبیه VPN/تونل پیدا نشد.",

    # ------------------------------------------------------------ HTTP
    "Checking plain HTTP for block pages ...": "در حال بررسی HTTP ساده برای صفحه‌ی مسدودسازی ...",
    "Could not run the check: {}.": "اجرای بررسی ممکن نشد: {1}.",
    "redirect to a private address ({})": "تغییر مسیر به یک آدرس خصوصی ({1})",
    "Signs of a block page: {}.": "نشانه‌های صفحه‌ی مسدودسازی: {1}.",
    "No block page indicators in the plain HTTP response.": "در پاسخ HTTP ساده نشانه‌ای از صفحه‌ی مسدودسازی نبود.",
    "Testing plain HTTP ...": "در حال آزمون HTTP ساده ...",
    "Failed: {}": "ناموفق: {1}",
    "Testing HTTPS ...": "در حال آزمون HTTPS ...",
    "Testing HTTP/2 ...": "در حال آزمون HTTP/2 ...",
    "Server negotiated HTTP/2 in {} ms.": "سرور HTTP/2 را در {1} میلی‌ثانیه مذاکره کرد.",
    "Connected, but negotiated {} instead of HTTP/2.": "اتصال برقرار شد، اما به‌جای HTTP/2 مقدار {1} مذاکره شد.",
    "The optional 'h2' package is not installed - HTTP/2 could not be tested.":
        "بسته‌ی اختیاری «h2» نصب نیست؛ HTTP/2 آزموده نشد.",
    "Checking HTTP/3 (QUIC) support ...": "در حال بررسی پشتیبانی از HTTP/3 (QUIC) ...",
    "QUIC handshake with {} succeeded in {} ms.": "دست‌دهی QUIC با {1} در {2} میلی‌ثانیه موفق شد.",
    "QUIC handshake failed: {}": "دست‌دهی QUIC ناموفق بود: {1}",
    "Server advertises HTTP/3 via Alt-Svc header (indirect hint, QUIC handshake not performed - install 'aioquic' for a real test).":
        "سرور HTTP/3 را از طریق هدر Alt-Svc اعلام می‌کند (نشانه‌ی غیرمستقیم؛ دست‌دهی QUIC انجام نشد - برای آزمون واقعی «aioquic» را نصب کنید).",
    "Server did not advertise HTTP/3 via Alt-Svc (install 'aioquic' for a real QUIC handshake test).":
        "سرور HTTP/3 را از طریق Alt-Svc اعلام نکرد (برای آزمون واقعی دست‌دهی QUIC «aioquic» را نصب کنید).",
    "Could not check Alt-Svc hint: {}": "بررسی نشانه‌ی Alt-Svc ممکن نشد: {1}",
    "Testing HTTP redirect handling ...": "در حال آزمون مدیریت تغییر مسیر HTTP ...",
    "Followed {} redirect(s) to {}.": "{1} تغییر مسیر دنبال شد تا {2}.",
    "No redirect occurred; final response received directly.": "تغییر مسیری رخ نداد؛ پاسخ نهایی مستقیم دریافت شد.",
    "Testing response compression ...": "در حال آزمون فشرده‌سازی پاسخ ...",
    "Server compressed the response using '{}'.": "سرور پاسخ را با «{1}» فشرده کرد.",
    "Server did not compress the response body.": "سرور بدنه‌ی پاسخ را فشرده نکرد.",
    "Testing TCP connection reuse (keep-alive) ...": "در حال آزمون استفاده‌ی مجدد از اتصال TCP (keep-alive) ...",
    "Two requests shared one TCP connection (first {} ms, second {} ms).":
        "دو درخواست یک اتصال TCP را به اشتراک گذاشتند (اولی {1} میلی‌ثانیه، دومی {2} میلی‌ثانیه).",
    "The server or network closed the connection between requests ({} connections opened for {} requests).":
        "سرور یا شبکه اتصال را بین درخواست‌ها بست ({1} اتصال برای {2} درخواست باز شد).",

    # --------------------------------------------------------- latency / MTU
    "Measuring latency to {} ({}) ...": "در حال اندازه‌گیری تأخیر تا {1} ({2}) ...",
    "Latency to {}": "تأخیر تا {1}",
    "No replies received.": "پاسخی دریافت نشد.",
    "Avg {} ms, jitter {} ms, loss {}%.": "میانگین {1} میلی‌ثانیه، جیتر {2} میلی‌ثانیه، افت {3}٪.",
    "Discovering path MTU to {} ...": "در حال کشف MTU مسیر تا {1} ...",
    "Could not get a baseline reply even at {} bytes MTU - ICMP may be blocked, so MTU could not be measured.":
        "حتی با MTU برابر {1} بایت پاسخ پایه‌ای دریافت نشد؛ ممکن است ICMP مسدود باشد و MTU اندازه‌گیری نشد.",
    "Estimated path MTU is {} bytes (standard Ethernet MTU).": "MTU تخمینی مسیر {1} بایت است (MTU استاندارد اترنت).",
    "Estimated path MTU is {} bytes - slightly below the standard 1500, which can happen with VPNs or tunnels but may also cause minor fragmentation issues.":
        "MTU تخمینی مسیر {1} بایت است؛ کمی کمتر از ۱۵۰۰ استاندارد، که با VPN یا تونل پیش می‌آید ولی ممکن است مشکلات جزئی تکه‌تکه‌شدن (fragmentation) هم بسازد.",
    "Estimated path MTU is only {} bytes - noticeably below standard, which can cause slow or failing connections for larger packets.":
        "MTU تخمینی مسیر فقط {1} بایت است؛ به‌وضوح کمتر از استاندارد، که می‌تواند برای بسته‌های بزرگ‌تر باعث کندی یا شکست اتصال شود.",

    # -------------------------------------------------------- protocol tests
    "Checking UDP/443 (QUIC transport) reachability ...": "در حال بررسی دسترس‌پذیری UDP/443 (لایه‌ی QUIC) ...",
    "Received a UDP response on port 443 in {} ms.": "پاسخ UDP روی پورت 443 در {1} میلی‌ثانیه دریافت شد.",
    "No UDP/443 response (see HTTP Test module for a full QUIC handshake result, which is more conclusive).":
        "پاسخی روی UDP/443 نیامد (نتیجه‌ی کامل دست‌دهی QUIC را که قطعی‌تر است در ماژول «آزمون HTTP» ببینید).",
    "UDP/443 rejected with ICMP port-unreachable.": "UDP/443 با ICMP port-unreachable رد شد.",
    "Socket error: {}": "خطای سوکت: {1}",
    "Testing DNS-over-HTTPS via {} ...": "در حال آزمون DNS-over-HTTPS از طریق {1} ...",
    "DNS-over-HTTPS ({})": "DNS-over-HTTPS ({1})",
    "DoH query succeeded in {} ms.": "پرس‌وجوی DoH در {1} میلی‌ثانیه موفق شد.",
    "DoH endpoint returned HTTP {}.": "نقطه‌ی پایانی DoH پاسخ HTTP {1} داد.",
    "DoH request failed: {}": "درخواست DoH ناموفق بود: {1}",
    "Testing DNS-over-TLS via {} ...": "در حال آزمون DNS-over-TLS از طریق {1} ...",
    "DNS-over-TLS ({})": "DNS-over-TLS ({1})",
    "DoT query succeeded in {} ms.": "پرس‌وجوی DoT در {1} میلی‌ثانیه موفق شد.",
    "TLS handshake succeeded but no DNS response was returned.": "دست‌دهی TLS موفق بود اما پاسخ DNS برنگشت.",
    "DoT failed: {}": "DoT ناموفق بود: {1}",
    "Testing ICMP echo ...": "در حال آزمون ICMP echo ...",
    "ICMP echo replies received - ICMP is not blocked.": "پاسخ ICMP echo دریافت شد؛ ICMP مسدود نیست.",
    "No ICMP echo replies - ICMP may be blocked or rate limited on this path.":
        "پاسخ ICMP echo نیامد؛ ممکن است ICMP در این مسیر مسدود یا محدود شده باشد.",
    "Testing WebSocket (wss://) handshake ...": "در حال آزمون دست‌دهی WebSocket (wss://) ...",
    "The optional 'websockets' package is not installed.": "بسته‌ی اختیاری «websockets» نصب نیست.",
    "WebSocket handshake timed out.": "مهلت دست‌دهی WebSocket تمام شد.",
    "WebSocket handshake failed: {}": "دست‌دهی WebSocket ناموفق بود: {1}",
    "WebSocket handshake and echo round-trip succeeded.": "دست‌دهی WebSocket و رفت‌وبرگشت echo موفق بود.",

    # ------------------------------------------------- protocol whitelist
    "The probe server could not be resolved.": "نام سرور پروب حل نشد.",
    "Baseline TLS handshake before the protocol probe ...": "دست‌دهی TLS پایه پیش از پروب پروتکل ...",
    "A normal TLS handshake to the probe server failed first, so the probe would not be meaningful.":
        "ابتدا یک دست‌دهی TLS عادی با سرور پروب ناموفق بود، پس پروب معنادار نخواهد بود.",
    "Sending a non-protocol payload to the control port ...": "در حال ارسال داده‌ی غیرپروتکلی به پورت کنترل ...",
    "Sending a non-protocol payload to the monitored port ...": "در حال ارسال داده‌ی غیرپروتکلی به پورت تحت‌نظر ...",
    "The server reacted to the odd payload on the control port but stayed silent on port 443. That matches a filter that drops non-standard traffic on port 443, though a server quirk could cause the same result.":
        "سرور روی پورت کنترل به داده‌ی غیرعادی واکنش نشان داد اما روی پورت 443 ساکت ماند. این با فیلتری سازگار است که ترافیک "
        "غیراستاندارد را روی پورت 443 حذف می‌کند، هرچند ویژگی خاص سرور هم می‌تواند همین نتیجه را بدهد.",
    "Port 443 reacted to the odd payload like the control port did; no sign of a protocol whitelist.":
        "پورت 443 مانند پورت کنترل به داده‌ی غیرعادی واکنش نشان داد؛ نشانه‌ای از Protocol Whitelist نیست.",
    "The control port did not react either, so the two cannot be compared.":
        "پورت کنترل هم واکنشی نشان نداد، پس این دو قابل مقایسه نیستند.",
    "One of the two ports could not be reached, so the probe is inconclusive.":
        "به یکی از دو پورت دسترسی پیدا نشد، پس نتیجه‌ی پروب قطعی نیست.",

    # --------------------------------------------------- site reachability
    "Checking {} website(s) layer by layer ...": "در حال بررسی {1} وب‌سایت، لایه به لایه ...",
    "Site {} ({})": "سایت {1} ({2})",
    "DNS lookup failed - the name could not be resolved.": "جست‌وجوی DNS ناموفق بود؛ نام حل نشد.",
    "DNS returned only a private/loopback address ({}). That is typical of a block page or DNS tampering.":
        "DNS فقط یک آدرس خصوصی/loopback برگرداند ({1}). این نشانه‌ی معمول صفحه‌ی مسدودسازی یا دست‌کاری DNS است.",
    "TCP port 443 on {}: {}.": "پورت TCP 443 روی {1}: {2}.",
    "The server's certificate did not validate ({}). This can mean TLS interception, but also an antivirus/proxy or captive portal.":
        "گواهی سرور معتبر شناخته نشد ({1}). این می‌تواند به معنی شنود TLS باشد، اما آنتی‌ویروس/پروکسی یا captive portal هم می‌تواند علت باشد.",
    "TCP connected, but the TLS handshake was reset. Consistent with a device inspecting the SNI name, though not proof.":
        "TCP وصل شد اما دست‌دهی TLS ریست شد. با دستگاهی که نام SNI را بررسی می‌کند سازگار است، هرچند مدرک نیست.",
    "TCP connected, but the connection was closed during the TLS handshake. Consistent with SNI/ClientHello inspection, though not proof.":
        "TCP وصل شد اما اتصال در حین دست‌دهی TLS بسته شد. با بررسی SNI/ClientHello سازگار است، هرچند مدرک نیست.",
    "TCP connected, but the TLS handshake timed out (packets after the ClientHello may be dropped).":
        "TCP وصل شد اما مهلت دست‌دهی TLS تمام شد (ممکن است بسته‌های پس از ClientHello حذف شده باشند).",
    "TLS handshake failed: {}": "دست‌دهی TLS ناموفق بود: {1}",
    "TLS worked but the HTTPS request failed ({}).": "TLS کار کرد اما درخواست HTTPS ناموفق بود ({1}).",
    "The server answered HTTP 451 (unavailable for legal reasons), which is an explicit block page status.":
        "سرور با HTTP 451 (غیرقابل‌دسترس به دلایل قانونی) پاسخ داد که یک وضعیت صریح صفحه‌ی مسدودسازی است.",
    "The site redirected to a private address ({}), which is typical of a block page.":
        "سایت به یک آدرس خصوصی ({1}) تغییر مسیر داد، که نشانه‌ی معمول صفحه‌ی مسدودسازی است.",
    "Reachable on every layer (HTTP {}, DNS {} ms, TCP {} ms, TLS {} ms).":
        "در همه‌ی لایه‌ها در دسترس است (HTTP {1}، DNS {2} میلی‌ثانیه، TCP {3} میلی‌ثانیه، TLS {4} میلی‌ثانیه).",
    "Even the control sites failed, so the connection itself looks unhealthy. Results for the other sites say little about site-specific blocking.":
        "حتی سایت‌های کنترل هم ناموفق بودند، پس خودِ اتصال سالم به نظر نمی‌رسد. نتایج سایت‌های دیگر درباره‌ی مسدودسازیِ مخصوص هر سایت اطلاعات کمی می‌دهد.",
    "{} of {} test site(s) failed ({}) while the control sites worked. That points to something specific to those sites rather than a general outage - a possibility, not a certainty.":
        "{1} از {2} سایت آزمون ناموفق بود ({3}) در حالی که سایت‌های کنترل کار کردند. این به چیزی مخصوص همان سایت‌ها اشاره دارد، نه قطعی عمومی؛ یک احتمال است، نه قطعیت.",
    "All {} test site(s) were reachable on every layer.": "هر {1} سایت آزمون در همه‌ی لایه‌ها در دسترس بود.",

    # ------------------------------------------------------------ TCP
    "could not resolve target: {}": "نام هدف حل نشد: {1}",
    "Scanning {} TCP ports on {} ...": "در حال اسکن {1} پورت TCP روی {2} ...",
    "TCP {} ({})": "TCP {1} ({2})",
    "{} - {} ms": "{1} - {2} میلی‌ثانیه",

    # ----------------------------------------------------------- stall
    "Control request for the TCP stall test ...": "درخواست کنترلی برای آزمون توقف TCP ...",
    "The test server could not be reached with a tiny request, so the result would be meaningless ({}).":
        "با یک درخواست بسیار کوچک هم به سرور آزمون دسترسی پیدا نشد، پس نتیجه بی‌معنا می‌بود ({1}).",
    "Downloading {} KB to look for stalls ...": "در حال دانلود {1} کیلوبایت برای یافتن توقف ...",
    "All {} KB arrived; no stall pattern observed.": "هر {1} کیلوبایت رسید؛ الگوی توقفی دیده نشد.",
    "The tiny request worked, but the transfer died after about {} KB ({}). That matches the '16-20 KB' pattern reported for some filtering systems, though a flaky connection could produce the same symptom.":
        "درخواست کوچک کار کرد اما انتقال پس از حدود {1} کیلوبایت متوقف شد ({2}). این با الگوی «۱۶ تا ۲۰ کیلوبایت» که برای برخی سامانه‌های "
        "فیلترینگ گزارش شده سازگار است، هرچند اتصال ناپایدار هم می‌تواند همین نشانه را بدهد.",
    "The transfer failed almost immediately ({} bytes, {}) although the tiny request worked.":
        "انتقال تقریباً بلافاصله شکست خورد ({1} بایت، {2}) با اینکه درخواست کوچک کار کرده بود.",
    "The transfer was interrupted after {} KB of {} KB ({}). This is outside the typical filtering range and more likely a general connection problem.":
        "انتقال پس از {1} کیلوبایت از {2} کیلوبایت قطع شد ({3}). این خارج از بازه‌ی معمول فیلترینگ است و بیشتر به مشکل عمومی اتصال می‌خورد.",
    "stalled": "متوقف شد",
    "incomplete response": "پاسخ ناقص",

    # ------------------------------------------------------------- TLS
    "Certificate verification failed: {}": "اعتبارسنجی گواهی ناموفق بود: {1}",
    "TLS error: {}": "خطای TLS: {1}",
    "Handshake timed out.": "مهلت دست‌دهی تمام شد.",
    "Connection error: {}": "خطای اتصال: {1}",
    "Testing TLS with {} ...": "در حال آزمون TLS با {1} ...",
    "TLS 1.3 Handshake ({})": "دست‌دهی TLS 1.3 ({1})",
    "TLS 1.2 Handshake ({})": "دست‌دهی TLS 1.2 ({1})",
    "Success in {} ms. Cipher: {}": "موفق در {1} میلی‌ثانیه. رمزنگاری: {2}",
    "Certificate Validation ({})": "اعتبارسنجی گواهی ({1})",
    "Certificate chain validated successfully by the OS trust store.":
        "زنجیره‌ی گواهی با موفقیت توسط مخزن اعتماد سیستم‌عامل تأیید شد.",
    "Could not complete a validated handshake to check the certificate.":
        "برای بررسی گواهی، دست‌دهیِ تأییدشده کامل نشد.",
    "SNI Support ({})": "پشتیبانی از SNI ({1})",
    "Server returned a certificate matching the requested SNI name.": "سرور گواهی‌ای برگرداند که با نام SNI درخواستی مطابقت دارد.",
    "SNI support could not be confirmed because no handshake completed.": "پشتیبانی از SNI تأیید نشد، چون هیچ دست‌دهی کامل نشد.",
    "ALPN Negotiation ({})": "مذاکره‌ی ALPN ({1})",
    "Server selected '{}' via ALPN.": "سرور از طریق ALPN مقدار «{1}» را انتخاب کرد.",
    "No ALPN protocol was negotiated (HTTP/2 cannot be used on this path).":
        "هیچ پروتکل ALPN مذاکره نشد (در این مسیر نمی‌توان از HTTP/2 استفاده کرد).",
    "Cipher Suite ({})": "مجموعه‌ی رمزنگاری ({1})",
    "{} ({}, {} bits)": "{1} ({2}، {3} بیت)",
    "Probing for SNI-based filtering ...": "در حال بررسی فیلترینگ مبتنی بر SNI ...",
    "Could not resolve the probe server, so SNI filtering could not be tested.":
        "نام سرور پروب حل نشد، پس فیلترینگ SNI آزموده نشد.",
    "Same server, different outcomes: handshakes were cut for {} but worked for {}. This pattern is consistent with SNI-based filtering, though it is not proof.":
        "یک سرور، نتایج متفاوت: دست‌دهی برای {1} قطع شد اما برای {2} کار کرد. این الگو با فیلترینگ مبتنی بر SNI سازگار است، هرچند مدرک نیست.",
    "Every handshake to {} failed regardless of SNI name, so this looks like a general block of that address or of TLS, not SNI filtering.":
        "همه‌ی دست‌دهی‌ها با {1} صرف‌نظر از نام SNI ناموفق بود، پس این بیشتر شبیه مسدودسازی عمومیِ آن آدرس یا TLS است، نه فیلترینگ SNI.",
    "No handshake could be completed for any name, so SNI filtering could not be assessed.":
        "برای هیچ نامی دست‌دهی کامل نشد، پس فیلترینگ SNI قابل ارزیابی نبود.",
    "Handshakes behaved the same for every SNI name tested.": "دست‌دهی برای همه‌ی نام‌های SNI آزموده‌شده یکسان رفتار کرد.",

    # ------------------------------------------------------------- UDP
    "UDP {} ({})": "UDP {1} ({2})",
    "Could not resolve target host '{}'.": "نام میزبان هدف «{1}» حل نشد.",
    "Reachable - received {} byte response in {} ms.": "در دسترس؛ پاسخ {1} بایتی در {2} میلی‌ثانیه دریافت شد.",
    "No response within timeout (may be normal for UDP, or blocked).":
        "در مهلت تعیین‌شده پاسخی نیامد (برای UDP ممکن است عادی باشد، یا مسدود شده باشد).",
    "Port unreachable (ICMP rejection received) - actively blocked/closed.":
        "پورت در دسترس نیست (رد ICMP دریافت شد)؛ به‌طور فعال مسدود/بسته است.",
    "Probing {} UDP ports ...": "در حال بررسی {1} پورت UDP ...",
    "Probing UDP port {} ...": "در حال بررسی پورت UDP {1} ...",

    # ------------------------------------------------------------- VPN
    "This only reports raw transport-level reachability of common VPN ports. It does NOT connect to any VPN and does NOT indicate whether a VPN service would actually function.":
        "این فقط دسترس‌پذیری خامِ لایه‌ی انتقال برای پورت‌های رایج VPN را گزارش می‌کند. به هیچ VPN‌ای وصل "
        "نمی‌شود و نشان نمی‌دهد یک سرویس VPN واقعاً کار خواهد کرد یا نه.",
    "Checking common VPN TCP transport ports ...": "در حال بررسی پورت‌های رایج انتقال TCP برای VPN ...",
    "VPN TCP {} appears {}": "پورت VPN TCP {1}: {2}",
    "Connectivity check only - target {}:{} -> {}.": "فقط بررسی اتصال - هدف {1}:{2} ← {3}.",
    "Checking common VPN UDP transport ports ...": "در حال بررسی پورت‌های رایج انتقال UDP برای VPN ...",
    "VPN UDP {} connectivity": "اتصال VPN UDP {1}",

    # ----------------------------------------------------------- worker
    "Starting: {}": "شروع: {1}",
    "This module could not complete due to an internal error: {}": "این ماژول به‌دلیل یک خطای داخلی کامل نشد: {1}",
    "Run cancelled.": "اجرا لغو شد.",
    "All tests completed.": "همه‌ی آزمون‌ها انجام شد.",

    # ---------------------------------------------------------- exporter
    "INTERNET CONNECTIVITY & PROTOCOL ANALYZER - REPORT": "گزارش تحلیلگر اتصال اینترنت و پروتکل‌ها",
    "Generated: {}": "زمان تولید: {1}",
    "Profile: {}": "پروفایل: {1}",
    "-- Network Information --": "-- اطلاعات شبکه --",
    "Public IP     : {}": "آی‌پی عمومی      : {1}",
    "ISP           : {}": "ISP              : {1}",
    "Country       : {}": "کشور            : {1}",
    "City          : {}": "شهر             : {1}",
    "IPv4 Available: {}": "IPv4 در دسترس   : {1}",
    "IPv6 Available: {}": "IPv6 در دسترس   : {1}",
    "DNS Servers   : {}": "سرورهای DNS     : {1}",
    "Adapter       : {}": "کارت شبکه       : {1}",
    "Gateway       : {}": "Gateway          : {1}",
    "Internet OK   : {}": "اتصال اینترنت   : {1}",
    "MODULE: {}  [{}]": "ماژول: {1}  [{2}]",
    "ANALYSIS / POSSIBLE INTERPRETATIONS (probabilistic, not definitive)":
        "تحلیل / تفسیرهای ممکن (احتمالی، نه قطعی)",
    "Duration (ms)": "مدت (میلی‌ثانیه)",
    "Check": "بررسی",
    "Status": "وضعیت",
    "Message": "پیام",
    "Duration": "مدت",
    "Test Results": "نتایج آزمون‌ها",
    "Analysis (probabilistic interpretations, not definitive claims)":
        "تحلیل (تفسیرهای احتمالی، نه ادعای قطعی)",
    "Generated": "زمان تولید",
    "Duration: {} s": "مدت اجرا: {1} ثانیه",
    "Location": "موقعیت",
    "IPv4 / IPv6": "IPv4 / IPv6",
    "Internet Connectivity & Protocol Analyzer - Report": "گزارش تحلیلگر اتصال اینترنت و پروتکل‌ها",
    "Unsupported export format: {}": "قالب خروجی پشتیبانی نمی‌شود: {1}",
}

# Messages of the layered diagnostic engine (kept in their own file to stay readable).
from app.i18n_fa_diag import DIAG_FA  # noqa: E402

DYNAMIC_FA.update(DIAG_FA)
UI_FA.update({"Key findings": "یافته‌های کلیدی",
              "Technical evidence": "شواهد فنی", "Root cause analysis": "تحلیل علت اصلی",
              "Overall summary": "خلاصه‌ی کلی"})
