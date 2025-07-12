#!/bin/bash

# Write the frontend (index.html)

set -e

echo "Writing frontend files..."

INSTALL_DIR="/opt/wingbits-station-web"
FRONTEND_DIR="$INSTALL_DIR/frontend"

# ========== index.html file ==========
cat > "$FRONTEND_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Wingbits Station Web Config</title>
  <link rel="icon" type="image/png" href="https://wingbits.com/apple-icon.png?34e8dd62bf865c3e" />
  <style>
  .tabs-bar {
  display: flex;
  gap: 0px;
  border-bottom: 2px solid #e2e8f0;
  margin-bottom: 22px;
  margin-top: 18px;
}
.tab-btn {
  background: none;
  color: #202540;
  border: none;
  border-bottom: 3px solid transparent;
  padding: 11px 32px 10px 32px;
  margin: 0;
  font-size: 1.13em;
  font-weight: 600;
  cursor: pointer;
  transition: 0.13s;
  border-radius: 13px 13px 0 0;
  outline: none;
}
.tab-btn.active {
  background: #f4f7fd;
  color: #1976d2;
  border-bottom: 3px solid #2196f3;
  font-weight: bold;
}
.tab-content {
  display: none;
  min-height: 200px;
}
.tab-content.active {
  display: block;
  animation: fadein .4s;
}
@keyframes fadein {
  from {opacity:0;}
  to {opacity:1;}
}
  body {
    background: #f5f8fe;
    font-family: 'Segoe UI', 'system-ui', Arial, sans-serif;
    margin: 0;
    padding: 0;
    direction: ltr;
  }
  .container {
    display: flex;
    height: 100vh;
    width: 100vw;
  }
  .sidebar {
    background: #1a2940;
    color: #fff;
    width: 200px;
    min-width: unset;
    padding: 24px 4px 0 4px;
    display: flex;
    flex-direction: column;
    align-items: center;
    border-top-right-radius: 22px;
    border-bottom-right-radius: 22px;
    box-shadow: 2px 0 24px #0002;
	overflow-y: auto;
    max-height: 100vh;
    /* Hidden by default until authenticated */
    display: none; 
  }
  .logo {
    width: 38px;
    margin-bottom: 12px;
    border-radius: 12px;
    background: #fff;
    box-shadow: 0 2px 16px #0003;
  }
  .side-title {
    margin-bottom: 13px;
    font-size: 1.15rem;
    font-weight: 700;
    text-align: center;
    letter-spacing: 0.01em;
    white-space: pre-line;
  }
  .side-menu {
    width: 100%;
    margin-bottom: 18px;
  }
  .side-menu button {
    background: none;
    border: none;
    color: #fff;
    font-size: 1.03rem;
    width: 100%;
    padding: 10px 0 10px 7px;
    margin-bottom: 4px;
    text-align: left;
    cursor: pointer;
    border-radius: 8px;
    transition: background 0.16s;
    font-weight: 500;
  }
  .lang-switch {
    margin-top: auto;
    margin-bottom: 11px;
    width: 100%;
    display: flex;
    gap: 4px;
  }
  .lang-switch button {
    flex: 1;
    border-radius: 7px;
    border: none;
    background: #fff;
    color: #1a2940;
    font-weight: 600;
    font-size: 0.98rem;
    padding: 7px 0;
    cursor: pointer;
    transition: background 0.15s;
  }
  .lang-switch button.active {
    background: #1366f6;
    color: #fff;
    box-shadow: 0 2px 8px #1366f650;
  }
  .main {
    flex: 1;
    padding: 48px 7vw;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }
  .form-group {
    margin-bottom: 26px;
  }
  .label {
    font-weight: 600;
    margin-bottom: 7px;
    display: block;
    font-size: 1.06em;
    color: #1a2940;
  }
  input, select, textarea, button.action {
    font-size: 1rem;
    padding: 10px 12px;
    border-radius: 9px;
    border: 1px solid #e3eaf4;
    background: #f6faff;
    margin-bottom: 9px;
    width: 100%;
    transition: border 0.16s;
    box-sizing: border-box;
  }
  input:focus, select:focus, textarea:focus {
    border-color: #1366f6;
    outline: none;
  }
  button.action {
    background: #1366f6;
    color: #fff;
    border: none;
    cursor: pointer;
    margin-top: 6px;
    transition: background 0.17s, box-shadow 0.18s;
    box-shadow: 0 1px 5px #1366f640;
    font-weight: 600;
    letter-spacing: 0.02em;
  }
  button.action:hover {
    background: #0956cb;
    box-shadow: 0 2px 12px #1366f655;
  }
  .result-block {
    background: #fff;
    border-radius: 18px;
    padding: 18px 18px;
    margin: 20px 0 10px 0;
    box-shadow: 0 2px 14px #0001;
    direction: ltr;
    font-family: monospace;
    font-size: 1.07em;
    overflow-x: auto;
    white-space: pre-wrap;
    color: #333;
  }
  .desc-block {
    font-size: 1.07em;
    color: #1366f6;
    margin-top: 9px;
    margin-bottom: 19px;
  }
  hr {
    border: none;
    height: 2px;
    background: #e4eaf6;
    border-radius: 2px;
    margin: 18px 0 22px 0;
  }
  .diagnostics-section {
    background-color: #ffffff;
    padding: 24px;
    border-radius: 15px;
    margin-bottom: 25px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
  }
  .diagnostics-section h3 {
    margin-top: 0;
    margin-bottom: 8px;
    font-size: 1.4em;
    color: #1a2940;
  }
  .diagnostics-section p {
    margin-top: 0;
    margin-bottom: 20px;
    color: #555;
    font-size: 1.05em;
  }
  .diagnostics-section button.action {
    width: 100%;
    margin-bottom: 10px;
    padding: 12px;
    font-size: 1.1em;
  }
  .diag-command-item {
      margin-bottom: 20px;
  }
  .log-link-result {
    margin-top: 10px;
    padding: 10px;
    background-color: #e9f5ff;
    border: 1px solid #b3d7ff;
    border-radius: 8px;
    font-family: monospace;
    word-wrap: break-word;
  }
  @media (max-width: 700px) {
    .main { padding: 13px 1vw; }
    .sidebar { min-width: 66px; padding-left: 3px; padding-right: 3px;}
    .side-title { font-size: 1.06rem; }
    .logo { width: 38px; }
    .side-menu button { font-size: 0.98rem;}
    .lang-switch { font-size: 0.97rem;}
  }
  body.rtl .container {
  flex-direction: row-reverse;
}

body.rtl .sidebar {
  border-top-right-radius: 0;
  border-bottom-right-radius: 0;
  border-top-left-radius: 22px;
  border-bottom-left-radius: 22px;
  box-shadow: -2px 0 24px #0002;
}
body.rtl .sidebar {
  text-align: right;
}
body.rtl .side-menu button {
  text-align: right;
  padding-right: 12px;
}
body.rtl .main {
  text-align: right;
}

body.rtl .result-block,
body.rtl .desc-block,
body.rtl h2,
body.rtl h3,
body.rtl h4,
body.rtl .form-group,
body.rtl .tabs-bar,
body.rtl .tab-content,
body.rtl .tab-btn,
body.rtl input,
body.rtl select,
body.rtl textarea,
body.center button,
body.rtl table,
body.rtl #main-content,
body.rtl .diagnostics-section {
  direction: rtl;
  text-align: right;
}

/* Login Page Specific Styles */
.login-container {
    display: flex;
    justify-content: center; /* Center horizontally */
    align-items: center; /* Center vertically */
    height: 100vh;
    width: 100vw; /* Ensure it takes full width to center content */
    background: #f5f8fe;
}
.login-box {
    background: #fff;
    padding: 40px;
    border-radius: 15px;
    box-shadow: 0 5px 25px rgba(0,0,0,0.1);
    width: 100%;
    max-width: 400px;
    text-align: center;
    margin: auto; /* This helps center the block itself within its flex container */
}
.login-box h2 {
    margin-bottom: 30px;
    color: #1a2940;
    font-size: 1.8em;
}
.login-box input[type="text"],
.login-box input[type="password"] {
    width: calc(100% - 24px);
    padding: 12px;
    margin-bottom: 20px;
    border: 1px solid #e3eaf4;
    border-radius: 8px;
    font-size: 1.1em;
}
.login-box button.action {
    width: 100%;
    padding: 12px;
    font-size: 1.1em;
    margin-top: 10px;
}
.login-message {
    margin-top: 20px;
    color: red;
    font-weight: bold;
}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div class="container" id="container">
    <div class="sidebar" id="sidebar">
      <img class="logo" src="https://wingbits.com/apple-icon.png?34e8dd62bf865c3e" alt="Wingbits" />
      <div class="side-title" id="side-title">Wingbits Web Config</div>
      <div class="side-menu" id="side-menu">
        </div>
      <div class="lang-switch">
        <button id="en-btn" class="active" onclick="setLang('en')">EN</button>
        <button id="ar-btn" onclick="setLang('ar')">العربية</button>
      </div>
      <!-- Logout button is hidden by default and shown after login -->
      <button class="action" style="margin-top: auto; margin-bottom: 15px; width: 80%; display: none;" onclick="logoutUser()" id="logout-btn"></button>
    </div>
    <div class="main" id="main-content">
      </div>
  </div>

  <script>
    // --------- Interface text translation ----------
    const txt = {
      en: {
        main_title: "Wingbits Station Web Config",
        menu: [
          "Live Stats", "Set Gain", "QOL Options", "Diagnostics", "Wingbits Metrics", "Support Menu", "Restart", "Change Password", "URLs", "Help" // Reordered menu items
        ],
        readsb: "readsb Service",
        wingbits: "wingbits Service",
        tar1090: "tar1090 Service",
        graphs1090: "graphs1090 Service",
        btn_status: "Status",
        btn_restart: "Restart",
        btn_logs: "Logs",
        btn_update: "Update",
        btn_geosigner: "GeoSigner Info",
        btn_version: "Version",
        btn_set_gain: "Set Gain",
        btn_colorscheme: "Colorscheme",
        btn_routeinfo: "Route Info",
        btn_dark: "Dark",
        btn_light: "Light",
        btn_enable: "Enable",
        btn_disable: "Disable",
        btn_signalreport: "Signal Report",
        btn_debug: "Debug",
        logs_head: "View Logs",
        settings_head: "System Info & Tools",
        reboot: "Reboot",
        shutdown: "Shutdown",
        about: "About & Help",
        please_wait: "Please wait...",
        gain_value: "Gain value",
        apply: "Apply",
        service: "Service",
        select: "Select",
        colorscheme: "Colorscheme",
        pi_restart: "Reboot Device",
        pi_shutdown: "Shutdown Device",
        info_system: "System Info",
        yes: "Yes",
        no: "No",
        logout: "Logout",
        change_password: "Change Password",
        old_password: "Old Password",
        new_password: "New Password",
        confirm_new_password: "Confirm New Password",
        update_password: "Update Password",
        username: "Username",
        password: "Password",
        login: "Login",
        login_failed: "Login failed. Please check your username and password.",
        password_changed_success: "Password changed successfully. Please log in again.",
        password_change_fail: "Password change failed. Please check your old password and try again.",
        password_mismatch: "New passwords do not match.",
        password_too_short: "New password must be at least 6 characters long.",
        wingbits_install_needed: "Wingbits client not installed. Please install it from your 'My Stations' dashboard on wingbits.com.",
        wb_config_install_needed: "wb-config not installed. Please install it manually by running: curl -sL https://gitlab.com/wingbits/config/-/raw/master/wb-config/install.sh | sudo bash",
        return_to_normal_gain: "Return to Normal Gain Options",
        confirm_update_client: "Are you sure you want to update the Wingbits client?",
        update_in_progress: "An update is already in progress.",
        update_started: "Wingbits client update started. Checking progress...",
        update_finished: "Wingbits client update finished.",
        update_failed: "Wingbits client update failed.",
        fetching_logs: "Fetching update logs...",
        update_client_progress: "Wingbits Client Update Progress",
        update_log_placeholder: "Update logs will appear here...",
        wingbits_metrics: "Wingbits Metrics",
        diagnostics_title: "Diagnostics & Support Tools",
        generate_log_url_title: "Generate Log URL for Support",
        generate_log_url_desc: "Click a button to generate a temporary URL containing system logs. This is useful for sharing with the Wingbits support team.",
        generate_wingbits_readsb_link: "Generate Wingbits & readsb Logs Link",
        generate_all_logs_link: "Generate All Recent Logs Link",
        handy_commands_title: "Handy Diagnostic Commands",
        view_os_release: "View OS Release Details",
        view_usb_devices: "View USB Devices",
        check_voltage: "Check Voltage Throttling",
        view_wingbits_status_verbose: "View Wingbits Detailed Status",
        view_geosigner_info: "View GeoSigner Info",
        copy_link: "Copy Link",
        copied: "Copied!"
      },
      ar: {
        main_title: "إعداد محطة Wingbits عبر الويب",
        menu: [
          "الحالة الحية", "ضبط الكسب", "خيارات الجودة", "التشخيص", "مقاييس Wingbits", "الدعم", "إعادة/إيقاف التشغيل", "تغيير كلمة المرور", "روابط محلية", "حول" // Reordered menu items
        ],
        readsb: "خدمة readsb",
        wingbits: "خدمة wingbits",
        tar1090: "خدمة tar1090",
        graphs1090: "خدمة graphs1090",
        btn_status: "الحالة",
        btn_restart: "إعادة تشغيل",
        btn_logs: "السجلات",
        btn_update: "تحديث",
        btn_geosigner: "معلومات GeoSigner",
        btn_version: "الإصدار",
        btn_set_gain: "ضبط الكسب",
        btn_colorscheme: "مخطط الألوان",
        btn_routeinfo: "معلومات المسار",
        btn_dark: "غامق",
        btn_light: "فاتح",
        btn_enable: "تفعيل",
        btn_disable: "تعطيل",
        btn_signalreport: "تقرير الإشارة",
        btn_debug: "تصحيح",
        logs_head: "عرض السجلات",
        settings_head: "معلومات النظام وأدواته",
        reboot: "إعادة تشغيل",
        shutdown: "إيقاف تشغيل",
        about: "حول & مساعدة",
        please_wait: "يرجى الانتظار...",
        gain_value: "قيمة الكسب",
        apply: "تطبيق",
        service: "الخدمة",
        select: "اختر",
        colorscheme: "مخطط الألوان",
        pi_restart: "إعادة تشغيل الجهاز",
        pi_shutdown: "إيقاف تشغيل الجهاز",
        info_system: "معلومات النظام",
        yes: "نعم",
        no: "لا",
        logout: "تسجيل الخروج",
        change_password: "تغيير كلمة المرور",
        old_password: "كلمة المرور القديمة",
        new_password: "كلمة المرور الجديدة",
        confirm_new_password: "تأكيد كلمة المرور الجديدة",
        update_password: "تحديث كلمة المرور",
        username: "اسم المستخدم",
        password: "كلمة المرور",
        login: "تسجيل الدخول",
        login_failed: "فشل تسجيل الدخول. يرجى التحقق من اسم المستخدم وكلمة المرور.",
        password_changed_success: "تم تغيير كلمة المرور بنجاح. يرجى تسجيل الدخول مرة أخرى.",
        password_change_fail: "فشل تغيير كلمة المرور. يرجى التحقق من كلمة المرور القديمة والمحاولة مرة أخرى.",
        password_mismatch: "كلمتا المرور الجديدتان غير متطابقتين.",
        password_too_short: "يجب أن تتكون كلمة المرور الجديدة من 6 أحرف على الأقل.",
        wingbits_install_needed: "عميل Wingbits غير مثبت. يرجى تثبيته من لوحة معلومات 'محطاتي' على wingbits.com.",
        wb_config_install_needed: "wb-config غير مثبت. يرجى تثبيته يدويًا عن طريق تشغيل: curl -sL https://gitlab.com/wingbits/config/-/raw/master/wb-config/install.sh | sudo bash",
        return_to_normal_gain: "العودة لخيارات Gain العادية",
        confirm_update_client: "هل أنت متأكد أنك تريد تحديث عميل Wingbits؟",
        update_in_progress: "تحديث قيد التقدم بالفعل.",
        update_started: "بدأ تحديث عميل Wingbits. جاري التحقق من التقدم...",
        update_finished: "اكتمل تحديث عميل Wingbits.",
        update_failed: "فشل تحديث عميل Wingbits.",
        fetching_logs: "جاري جلب سجلات التحديث...",
        update_client_progress: "تقدم تحديث عميل Wingbits",
        update_log_placeholder: "ستظهر سجلات التحديث هنا...",
        wingbits_metrics: "مقاييس Wingbits",
        diagnostics_title: "أدوات التشخيص والدعم",
        generate_log_url_title: "إنشاء رابط للسجلات للدعم",
        generate_log_url_desc: "انقر فوق زر لإنشاء عنوان URL مؤقت يحتوي على سجلات النظام. هذا مفيد للمشاركة مع فريق دعم Wingbits.",
        generate_wingbits_readsb_link: "إنشاء رابط لسجلات Wingbits و readsb",
        generate_all_logs_link: "إنشاء رابط لجميع السجلات الحديثة",
        handy_commands_title: "أوامر تشخيص مفيدة",
        view_os_release: "عرض تفاصيل نظام التشغيل",
        view_usb_devices: "عرض أجهزة USB",
        check_voltage: "فحص انخفاض الجهد",
        view_wingbits_status_verbose: "عرض حالة Wingbits التفصيلية",
        view_geosigner_info: "عرض معلومات GeoSigner",
        copy_link: "نسخ الرابط",
        copied: "تم النسخ!"
      }
    };

    let LANG = localStorage.getItem("wb_lang") || "en";
    let AUTH_TOKEN = localStorage.getItem("auth_token");

    // --- Live Stats / Dashboard Variables (Defined Globally) ---
    let liveChart = null;
    let liveStatsHistory = [];
    let liveTimer = null;
    let updateLogTimer = null; // Global timer for update logs polling

    // --- Language Settings ---
    function setLang(l) {
      LANG = l;
      localStorage.setItem("wb_lang", l);
      document.body.dir = (l === "ar") ? "rtl" : "ltr";
	  document.body.classList.toggle("rtl", l === "ar");
      
      const enBtn = document.getElementById("en-btn");
      const arBtn = document.getElementById("ar-btn");
      if (enBtn) enBtn.classList.toggle("active", l === "en");
      if (arBtn) arBtn.classList.toggle("active", l === "ar");
      
      const sideTitle = document.getElementById("side-title");
      if (sideTitle) { // Check if element exists before accessing
        sideTitle.innerText = txt[LANG].main_title;
      }
      
      const logoutBtn = document.getElementById("logout-btn");
      if (logoutBtn) { // Check if element exists before accessing
        logoutBtn.innerText = txt[LANG].logout;
      }
      
      // Re-render the current page to apply new language
      const currentKey = document.querySelector('.side-menu button.active')?.dataset.key || 'live_stats';
      const currentSub = document.querySelector('.side-menu button.active')?.dataset.sub || '';
      const currentQolSub = document.querySelector('.side-menu button.active')?.dataset.qolSub || '';
      
      // Only re-render if not on the login page and main content elements exist
      if (document.getElementById('login-container') === null && document.getElementById('main-content')) {
        renderMenuPage(currentKey, currentSub, currentQolSub);
      }
    }

    // --- Sidebar Menu Control ---
    function renderMenu(activeKey = 'live_stats', supportSub = '', qolSub = '') {
      const mainMenu = [
        { key: 'live_stats', label: LANG === 'ar' ? 'الحالة الحية' : 'Live Stats' },
        { key: 'set_gain', label: LANG === 'ar' ? 'ضبط الكسب' : 'Set Gain' },
        { key: 'qol_options', label: LANG === 'ar' ? 'خيارات الجودة' : 'QOL Options' },
        { key: 'diagnostics', label: LANG === 'ar' ? 'التشخيص' : 'Diagnostics' },
        { key: 'wingbits_metrics', label: LANG === 'ar' ? 'مقاييس Wingbits' : 'Wingbits Metrics', isExternalLink: true, url: 'http://192.168.100.5:8088/metrics' }, // Moved Wingbits Metrics
        { key: 'support_menu', label: LANG === 'ar' ? 'الدعم' : 'Support Menu' },
        { key: 'restart', label: LANG === 'ar' ? 'إعادة/إيقاف التشغيل' : 'Restart' },
        { key: 'change_password', label: LANG === 'ar' ? 'تغيير كلمة المرور' : 'Change Password' },
        { key: 'urls', label: LANG === 'ar' ? 'روابط محلية' : 'URLs' }, // Moved URLs
        { key: 'help', label: LANG === 'ar' ? 'مساعدة' : 'Help' }
      ];
      let menu = '';
      for (let i = 0; i < mainMenu.length; ++i) {
        let isActive = (mainMenu[i].key === activeKey) ? "active" : "";
        
        // Handle external links
        if (mainMenu[i].isExternalLink) {
            menu += `<button class="${isActive}" data-key="${mainMenu[i].key}" onclick="window.open('${mainMenu[i].url}', '_blank')">${mainMenu[i].label}</button>`;
        } else {
            menu += `<button class="${isActive}" data-key="${mainMenu[i].key}" onclick="renderMenuPage('${mainMenu[i].key}')">${mainMenu[i].label}</button>`;
        }

        if (mainMenu[i].key === 'qol_options' && activeKey === 'qol_options') {
          menu += `
            <div style="margin-left:18px;">
              <button class="${qolSub==='graphs_colorscheme'?'active':''}" data-key="qol_options" data-qol-sub="graphs_colorscheme" onclick="renderMenuPage('qol_options', '', 'graphs_colorscheme')">${LANG === 'ar' ? 'مخطط ألوان graphs1090' : 'graphs1090 colorscheme'}</button>
              <button class="${qolSub==='tar_routes'?'active':''}" data-key="qol_options" data-qol-sub="tar_routes" onclick="renderMenuPage('qol_options', '', 'tar_routes')">${LANG === 'ar' ? 'مسارات tar1090' : 'tar1090 routes'}</button>
              <button class="${qolSub==='tar_heatmaps'?'active':''}" data-key="qol_options" data-qol-sub="tar_heatmaps" onclick="renderMenuPage('qol_options', '', 'tar_heatmaps')">${LANG === 'ar' ? 'خرائط الحرارة tar1090' : 'tar1090 heatmaps'}</button>
            </div>
          `;
        }
        if (mainMenu[i].key === 'support_menu' && activeKey === 'support_menu') {
          menu += `
            <div style="margin-left:18px;">
              <button class="${supportSub==='debug'?'active':''}" data-key="support_menu" data-sub="debug" onclick="renderMenuPage('support_menu','debug')">${LANG === 'ar' ? 'تصحيح' : 'Debug'}</button>
              <button class="${supportSub==='wingbits_status'?'active':''}" data-key="support_menu" data-sub="wingbits_status" onclick="renderMenuPage('support_menu','wingbits_status')">${LANG === 'ar' ? 'حالة wingbits' : 'wingbits status'}</button>
              <button class="${supportSub==='readsb_status'?'active':''}" data-key="support_menu" data-sub="readsb_status" onclick="renderMenuPage('support_menu','readsb_status')">${LANG === 'ar' ? 'حالة readsb' : 'readsb status'}</button>
              <button class="${supportSub==='wingbits_logs'?'active':''}" data-key="support_menu" data-sub="wingbits_logs" onclick="renderMenuPage('support_menu','wingbits_logs')">${LANG === 'ar' ? 'سجلات wingbits' : 'wingbits logs'}</button>
              <button class="${supportSub==='readsb_logs'?'active':''}" data-key="support_menu" data-sub="readsb_logs" onclick="renderMenuPage('support_menu','readsb_logs')">${LANG === 'ar' ? 'سجلات readsb' : 'readsb logs'}</button>
              <button class="${supportSub==='all_logs'?'active':''}" data-key="support_menu" data-sub="all_logs" onclick="renderMenuPage('support_menu','all_logs')">${LANG === 'ar' ? 'جميع السجلات الحديثة' : 'All recent logs'}</button>
              <button class="${supportSub==='last_install_log'?'active':''}" data-key="support_menu" data-sub="last_install_log" onclick="renderMenuPage('support_menu','last_install_log')">${LANG === 'ar' ? 'سجل التثبيت الأخير' : 'Last install log'}</button>
              <button class="${supportSub==='update_client'?'active':''}" data-key="support_menu" data-sub="update_client" onclick="confirmUpdateClient()">${LANG === 'ar' ? 'تحديث العميل' : 'Update Client'}</button>
            </div>
          `;
        }
      }
      // Ensure side-menu element exists before setting innerHTML
      const sideMenu = document.getElementById("side-menu");
      if (sideMenu) {
        sideMenu.innerHTML = menu;
      }
    }

    function renderMenuPage(key, sub = '', qolSub = '') {
      // Clear any existing intervals before rendering a new page
      if (liveTimer) {
        clearInterval(liveTimer);
        liveTimer = null;
      }
      if (updateLogTimer) { // Clear update log timer
        clearInterval(updateLogTimer);
        updateLogTimer = null;
      }

      const mainContent = document.getElementById("main-content");
      if (!mainContent) {
        console.error("Main content element not found.");
        return;
      }

      // If the key is 'wingbits_metrics', it's an external link, so we don't render a page.
      // The onclick handler in renderMenu already opens the new tab.
      if (key === 'wingbits_metrics') {
          mainContent.innerHTML = `<h2>${LANG === "ar" ? "مقاييس Wingbits" : "Wingbits Metrics"}</h2>
                                   <p>${LANG === "ar" ? "سيتم فتح صفحة المقاييس في تبويب جديد." : "The metrics page will open in a new tab."}</p>`;
          renderMenu(key); // Still highlight the menu item
          return;
      }


      if (key === 'support_menu') {
        renderMenu('support_menu', sub, qolSub);
        if (sub === 'debug') return renderDebug();
        if (sub === 'wingbits_status') return callAPI('/api/service/wingbits/status', 'GET', null, 'main-content');
        if (sub === 'readsb_status') return callAPI('/api/service/readsb/status', 'GET', null, 'main-content');
        if (sub === 'wingbits_logs') return callAPI('/api/service/wingbits/logs', 'GET', null, 'main-content');
        if (sub === 'readsb_logs') return callAPI('/api/service/readsb/logs', 'GET', null, 'main-content');
        if (sub === 'all_logs') return renderAllLogs();
        if (sub === 'last_install_log') return renderLastInstallLog();
        // The call to update_client is now handled by confirmUpdateClient()
        // if (sub === 'update_client') return callAPI('/api/service/wingbits/update-client', 'POST', null, 'main-content');
        mainContent.innerHTML = `<h2>${LANG === "ar" ? "يرجى اختيار خيار فرعي..." : "Please select a Support sub-option..."}</h2>`;
        return;
      }
      renderMenu(key, '', qolSub);
      if (key === 'live_stats') return renderLiveStats();
      if (key === 'set_gain') return renderSetGain();
      if (key === 'qol_options') {
        if (qolSub === 'graphs_colorscheme') return renderGraphsColorscheme();
        if (qolSub === 'tar_routes') return renderTarRoutes();
        if (qolSub === 'tar_heatmaps') return renderTarHeatmaps();
        mainContent.innerHTML = `<h2>Please select sub-option</h2>`; // Default for QOL if no sub-option selected
        return;
      }
      if (key === 'diagnostics') return renderDiagnosticsPage();
      if (key === 'urls') return renderURLs();
      if (key === 'restart') return renderPower();
      if (key === 'change_password') return renderChangePasswordPage(); // New page for password change
      if (key === 'help') return renderHelp();
      mainContent.innerHTML = `<h2>Please select sub-option</h2>`; // Default for other top-level menu items
    }

    // --- Live Stats / Dashboard Functions ---
    function renderLiveStats() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check

      mainContent.innerHTML = `
        <h2>${LANG === "ar" ? "لوحة مراقبة المحطة" : "Station Dashboard"}</h2>
        <div class="tabs-bar">
          <button class="tab-btn active" id="tabbtn_live" onclick="switchTab('live')">${LANG==="ar"?"الحالة الحية":"Live Stats"}</button>
          <button class="tab-btn" id="tabbtn_tools" onclick="switchTab('tools')">${LANG==="ar"?"أدوات":"Tools"}</button>
          <button class="tab-btn" id="tabbtn_alerts" onclick="switchTab('alerts')">${LANG==="ar"?"تنبيهات":"Alerts"}</button>
        </div>
        <div id="tabcontent_live" class="tab-content active"></div>
        <div id="tabcontent_tools" class="tab-content"></div>
        <div id="tabcontent_alerts" class="tab-content"></div>
      `;
      switchTab('live');
    }

    function switchTab(tab) {
      // Ensure elements exist before toggling classes
      const tabbtnLive = document.getElementById("tabbtn_live");
      const tabbtnTools = document.getElementById("tabbtn_tools");
      const tabbtnAlerts = document.getElementById("tabbtn_alerts");
      const tabcontentLive = document.getElementById("tabcontent_live");
      const tabcontentTools = document.getElementById("tabcontent_tools");
      const tabcontentAlerts = document.getElementById("tabcontent_alerts");

      if (tabbtnLive) tabbtnLive.classList.toggle("active", tab === "live");
      if (tabbtnTools) tabbtnTools.classList.toggle("active", tab === "tools");
      if (tabbtnAlerts) tabbtnAlerts.classList.toggle("active", tab === "alerts");
      
      if (tabcontentLive) tabcontentLive.classList.toggle("active", tab === "live");
      if (tabcontentTools) tabcontentTools.classList.toggle("active", tab === "tools");
      if (tabcontentAlerts) tabcontentAlerts.classList.toggle("active", tab === "alerts");

      // Clear any existing chart instance if it exists
      if (liveChart) {
        liveChart.destroy();
        liveChart = null;
      }
      if (liveTimer) {
        clearInterval(liveTimer);
        liveTimer = null;
      }
      if (updateLogTimer) { // Clear update log timer
        clearInterval(updateLogTimer);
        updateLogTimer = null;
      }

      if(tab === "live") {
        if (tabcontentLive) { // Ensure tabcontentLive exists
            tabcontentLive.innerHTML = `
            <div>
                <canvas id="liveChart" style="width:100%;max-width:1000px;height:180px;display:block;margin:auto"></canvas>
            </div>
            <div id="live-values" style="padding:14px 0 0 0;margin:0;display:flex;flex-direction:column;align-items:center;gap:5px;"></div>
            <div style="display:flex;justify-content:center;gap:12px;margin-bottom:18px;">
                <button class="action" onclick="updateLiveStats(true)">${LANG === "ar" ? "تحديث الآن" : "Refresh Now"}</button>
            </div>
            <div id="netstatus-block" style="margin:9px 0 16px 0;text-align:center"></div>
            <div style="margin:30px 0 0 0">
                <h3 style="font-size:1.1em;margin-bottom:7px">
                ${LANG==="ar" ? "معلومات النظام والهاردوير" : "System & Hardware Info"}
                </h3>
                <div id="system-info-block" style="font-family:monospace;font-size:1em"></div>
            </div>
            <div style="margin-top:10px;color:#888;font-size:0.92em" id="live-chart-note"></div>
            `;
            liveStatsHistory = [];
            // Call initLiveChart directly after setting innerHTML
            initLiveChart(); 
            liveTimer = setInterval(updateLiveStats, 60000); // 1 minute (60000 ms)
            setTimeout(updateLiveStats, 120);
            setTimeout(updateSystemInfoBlock, 140);
            setTimeout(updateNetStatusBlock, 180);
        }
      }
      else if(tab === "tools") {
        if (tabcontentTools) { // Ensure tabcontentTools exists
            tabcontentTools.innerHTML = `
            <div style="padding:24px;max-width:700px;margin:auto">
                <div style="margin-bottom:20px">
                <button class="action" onclick="copyDebugInfo()">
                    ${LANG === "ar" ? "نسخ بيانات التشخيص" : "Copy Debug Info"}
                </button>
                <span id="copy-debug-info-status" style="margin-left:12px;color:green"></span>
                </div>

                <div style="margin-bottom:20px">
                <button class="action" onclick="openUpdateModal()">
            ${LANG === "ar" ? "تثبيت/تحديث المكونات" : "Update/Reinstall Components"}
          </button>
                <span id="reinstall-all-status" style="margin-left:12px;color:blue"></span>
                </div>

                <div style="margin-bottom:20px">
            <h4 style="margin:8px 0 8px 0">${LANG === "ar" ? "إصدارات الخدمات" : "Client/Feeder Versions"}</h4>
            <div id="feeder-versions-block" style="font-family:monospace"></div>
            <button class="action" onclick="loadFeederVersions()" id="refresh-versions-btn">
              ${LANG==="ar" ? "تحديث إصدارات الخدمات" : "Refresh Versions"}
            </button>
          </div>

                <div style="margin-bottom:20px">
            <h4 style="margin:8px 0 8px 0">${LANG==="ar"?"حالة النظام والخدمات":"System/Service Status"}</h4>
            <div id="status-block" style="font-family:monospace"></div>
            <button class="action" onclick="loadStatusBlock()">${LANG==="ar"?"تحديث الحالة":"Refresh Status"}</button>
          </div>
            </div>
            `;
            setTimeout(()=>{
            loadFeederVersions();
            loadStatusBlock();
            },200);
        }
      }
      else if(tab === "alerts") {
        if (tabcontentAlerts) { // Ensure tabcontentAlerts exists
            tabcontentAlerts.innerHTML = `
            <div style="padding:24px;">
                <h3>${LANG === "ar" ? "تنبيهات وتشخيص" : "Alerts & Diagnostics"}</h3>
                <div id="alerts-content"></div>
                <button class="action" onclick="loadAlerts()">${LANG === "ar" ? "تحديث" : "Refresh"}</button>
            </div>
            `;
            loadAlerts();
        }
      }
    }

    function initLiveChart() {
      const liveChartCanvas = document.getElementById('liveChart');
      if (!liveChartCanvas) {
        console.error("Canvas element 'liveChart' not found for chart initialization.");
        return;
      }
      const ctx = liveChartCanvas.getContext('2d');
      liveChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: LANG === "ar" ? "رسائل/ثانية" : "Messages/sec",
              data: [],
              borderWidth: 2,
              fill: false,
              borderColor: 'rgb(75, 192, 192)',
              tension: 0.1
            },
            {
              label: LANG === "ar" ? "عدد الطائرات" : "Aircraft",
              data: [],
              borderWidth: 2,
              fill: false,
              borderColor: 'rgb(255, 99, 132)',
              tension: 0.1
            },
            {
              label: LANG === "ar" ? "استهلاك البيانات (KB)" : "Data Usage (KB)",
              data: [],
              borderWidth: 2,
              fill: false,
              borderColor: 'rgb(54, 162, 235)',
              tension: 0.1
            },
          ]
        },
        options: {
          responsive: true,
          scales: {
            y: { beginAtZero: true },
            x: { title: { display: true, text: LANG === "ar" ? "الوقت" : "Time" } }
          }
        }
      });
    }

    function updateLiveStats(manual = false) {
      fetch('/api/stats/live', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      }).then(res => res.json()).then(js => {
        const liveValuesEl = document.getElementById("live-values");
        if (js && js.ok) {
          const d = js.live;
          if (liveValuesEl) { // Check if element exists
            liveValuesEl.innerHTML = `
      <div style="display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:22px 14px;font-size:1.05em;margin:18px 0 0 0">
        <div>${LANG === "ar" ? "عدد الرسائل/ثانية" : "Messages/sec"}: <b>${d.messages_per_sec ?? "-"}</b></div>
        <div>${LANG === "ar" ? "عدد الطائرات الآن" : "Aircraft now"}: <b>${d.aircraft_now ?? "-"}</b></div>
        <div>${LANG === "ar" ? "طائرات مع موقع" : "Aircraft with pos"}: <b>${d.aircraft_with_pos ?? "-"}</b></div>
        <div>${LANG === "ar" ? "طائرات بدون موقع" : "Aircraft w/o pos"}: <b>${d.aircraft_without_pos ?? "-"}</b></div>
        <div>${LANG === "ar" ? "أقصى نطاق (كم)" : "Max range (km)"}: <b>${d.max_range_km ?? "-"}</b></div>
        <div>${LANG === "ar" ? "متوسط الإشارة (dB)" : "Avg signal (dB)"}: <b>${d.signal_avg_db ?? "-"}</b></div>
        <div>${LANG === "ar" ? "الإنترفيس الشبكي" : "Network Interface"}: <b>${d.network_iface || "-"}</b></div>
        <div>${LANG === "ar" ? "البيانات المستقبلة خلال 10 ثواني (KB)" : "Data Received/10s (KB)"}: <b>${d.data_usage_rx_kb ?? "-"}</b></div>
        <div>${LANG === "ar" ? "البيانات المرسلة خلال 10 ثواني (KB)" : "Data Sent/10s (KB)"}: <b>${d.data_usage_tx_kb ?? "-"}</b></div>
        <div>${LANG === "ar" ? "إجمالي المستلم (MB)" : "Total Received (MB)"}: <b>${(d.rx_total/1024/1024).toFixed(2)}</b></div>
        <div>${LANG === "ar" ? "إجمالي المرسل (MB)" : "Total Sent (MB)"}: <b>${(d.tx_total/1024/1024).toFixed(2)}</b></div>
      </div>
    `;
          }
          const timeLabel = new Date().toLocaleTimeString().slice(0, 8);
          liveStatsHistory.push({
            time: timeLabel,
            messages: d.messages_per_sec,
            aircraft: d.aircraft_now,
            data_kb: (Number(d.data_usage_rx_kb) || 0) + (Number(d.data_usage_tx_kb) || 0),
          });
          if (liveStatsHistory.length > 50) liveStatsHistory.shift();

          if (liveChart) {
            liveChart.data.labels = liveStatsHistory.map(x => x.time);
            liveChart.data.datasets[0].data = liveStatsHistory.map(x => x.messages);
            liveChart.data.datasets[1].data = liveStatsHistory.map(x => x.aircraft);
            liveChart.data.datasets[2].data = liveStatsHistory.map(x => x.data_kb);
            liveChart.update();
          }

          const liveChartNote = document.getElementById("live-chart-note");
          if (liveChartNote) { // Check if element exists
            liveChartNote.innerText = manual ? "Data refreshed manually." : "";
          }
        } else {
          if (liveValuesEl) { // Check if element exists
            liveValuesEl.innerHTML = `
              <div style="color:red;text-align:center;padding:20px;font-size:1.1em">
                ${LANG === "ar" ? "خطأ في جلب البيانات" : "Error:"} ${js.msg || "Unknown error"}
              </div>
            `;
          }
          if (liveChart) {
            liveChart.data.labels = [];
            liveChart.data.datasets.forEach(ds => ds.data = []);
            liveChart.update();
          }
        }
      }).catch(e => {
        const liveValuesEl = document.getElementById("live-values");
        if (liveValuesEl) { // Check if element exists
          liveValuesEl.innerHTML = `
            <div style="color:red;text-align:center;padding:20px;font-size:1.1em">
              ${LANG === "ar" ? "خطأ في الاتصال بالشبكة." : "Network error."}
            </div>
          `;
        }
      });
    }

    // Removed showStatsArchive() function as requested.

    // --- Set Gain Functions ---
    const GAIN_OPTIONS = [
        "auto", "58.0", "49.6", "48.0", "44.5", "43.4", "42.1", "40.2", "38.6", "37.2", "36.4",
        "33.8", "32.8", "29.7", "28.0", "25.4", "22.9", "20.7", "19.7", "16.6", "15.7",
        "14.4", "12.5", "8.7", "7.7", "3.7", "2.7", "1.4", "0.9", "0.0"
    ];

    function renderSetGain() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check

      mainContent.innerHTML = `
        <h2 style="color:#219150">${LANG === "ar" ? "ضبط الكسب" : "Set Gain"}</h2>
        <div class="result-block" style="color:#1a2940;font-size:1.04em;">
          <div><b>${LANG === "ar" ? "الكسب الحالي:" : "Current Gain:"}</b> <span id="current-gain-value">...</span></div>
        </div>
        
        <div id="simple-gain-section" style="margin-top:15px;">
            <label for="gain-select" class="label">${LANG === "ar" ? "اختر قيمة الكسب" : "Select Gain Value"}</label>
            <select id="gain-select" onchange="setGainFromDropdown()">
                ${GAIN_OPTIONS.map(option => {
                    // If the option is "auto" or "auto-verbose", display it without "db"
                    // Otherwise, append "db" to the option value
                    return `<option value="${option}">${option.includes("auto") ? option : option + "db"}</option>`;
                }).join('')}
            </select>
        </div>

        <div style="margin-top:20px;">
            <button class="action" id="toggle-gain-btn" onclick="toggleAdvancedGain()">${LANG === "ar" ? "ضبط الكسب المتقدم" : "Advanced Gain Settings"}</button>
        </div>

        <div id="advanced-gain-section" style="display:none; margin-top:20px;">
            <label for="advancedGainInput" class="label">${LANG === "ar" ? "أدخل قيمة الكسب المتقدمة" : "Enter Advanced Gain Value"}</label>
            <input id="advancedGainInput" type="text" placeholder="${txt[LANG].gain_value} (e.g. auto-verbose,12,-24,-6,35)" />
            <button class="action" onclick="setAdvancedGain()">${LANG === "ar" ? "تطبيق الكسب المتقدم" : "Apply Advanced Gain"}</button>
        </div>
        <div id="result-gain"></div>
      `;
      updateCurrentGainDisplay(); // Update current gain on page load
    }

    function toggleAdvancedGain() {
        const simpleSection = document.getElementById('simple-gain-section');
        const advancedSection = document.getElementById('advanced-gain-section');
        const toggleButton = document.getElementById('toggle-gain-btn');

        if (simpleSection.style.display === 'none') {
            simpleSection.style.display = 'block';
            advancedSection.style.display = 'none';
            if (toggleButton) {
                toggleButton.innerText = LANG === "ar" ? "ضبط الكسب المتقدم" : "Advanced Gain Settings";
            }
        } else {
            simpleSection.style.display = 'none';
            advancedSection.style.display = 'block';
            if (toggleButton) {
                toggleButton.innerText = LANG === "ar" ? "العودة لخيارات Gain العادية" : "Return to Normal Gain Options";
            }
        }
    }

    function setGainFromDropdown() {
        const gainSelect = document.getElementById('gain-select');
        if (gainSelect) {
            const selectedGain = gainSelect.value;
            setGain(selectedGain);
        }
    }

    function setAdvancedGain() {
        const advancedGainInput = document.getElementById('advancedGainInput');
        if (advancedGainInput) {
            const advancedGain = advancedGainInput.value;
            if (!advancedGain) {
                showCustomAlert(LANG === "ar" ? "قيمة الكسب المتقدمة مطلوبة" : "Advanced Gain value is required");
                return;
            }
            setGain(advancedGain);
        }
    }

    function setGain(gainValue) {
      callAPI('/api/service/readsb/set-gain', 'POST', {gain: gainValue}, 'result-gain').then(() => {
          updateCurrentGainDisplay(); // Update current gain after setting
      });
    }

    function updateCurrentGainDisplay() {
        const currentGainSpan = document.getElementById('current-gain-value');
        if (currentGainSpan) {
            currentGainSpan.innerText = LANG === "ar" ? "جاري التحميل..." : "Loading...";
            callAPI('/api/service/readsb/get-gain', 'GET', null, null, true).then((gainRes) => {
                if (gainRes && gainRes.gain) {
                    currentGainSpan.innerText = gainRes.gain;
                } else {
                    currentGainSpan.innerText = LANG === "ar" ? "غير محدد" : "Not set";
                }
            }).catch(() => {
                currentGainSpan.innerText = LANG === "ar" ? "خطأ في التحميل" : "Error loading";
            });
        }
    }

    // --- QOL Options Functions ---
    function renderGraphsColorscheme() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      let html = `
        <h2 style="color:#219150">${LANG === "ar" ? "وضع الرسوم البيانية" : "graphs1090 mode"}</h2>
        <div style="margin:20px 0;">${
          LANG === "ar"
            ? "اختر وضع العرض لصفحة الرسوم البيانية (graphs1090):"
            : "Which mode do you prefer for graphs1090 page/chart display?"
        }</div>
        <div style="display:flex;gap:20px;">
          <button class="action" onclick="setColorscheme('dark')">${LANG === "ar" ? "غامق" : "Dark"}</button>
          <button class="action" onclick="setColorscheme('default')">${LANG === "ar" ? "فاتح" : "Light"}</button>
        </div>
        <div id="result-graphs1090"></div>
      `;
      mainContent.innerHTML = html;
    }

    function setColorscheme(color) {
      callAPI('/api/service/graphs1090/colorscheme', 'POST', {color: color}, 'result-graphs1090');
    }

    function renderTarRoutes() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      let html = `
        <h2 style="color:#219150">${LANG === "ar" ? "مسارات الرحلات" : "Route Info"}</h2>
        <div style="margin:20px 0;">
          ${LANG === "ar" ? "تفعيل أو تعطيل معلومات مسار الرحلات في tar1090:" : "Enable or disable tar1090 route info:"}
        </div>
        <button class="action" onclick="toggleRouteInfo(true)">${LANG === "ar" ? "تفعيل" : "Enable"}</button>
        <button class="action" onclick="toggleRouteInfo(false)">${LANG === "ar" ? "تعطيل" : "Disable"}</button>
        <div id="result-tar1090"></div>
      `;
      mainContent.innerHTML = html;
    }
    function toggleRouteInfo(enable) {
      showCustomConfirm(LANG === "ar" ? "تفعيل معلومات المسار؟" : "Enable route info?", (confirmed) => {
        if (confirmed) {
          callAPI('/api/service/tar1090/route-info', 'POST', {enable: enable}, 'result-tar1090');
        }
      });
    }

    function renderTarHeatmaps() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      let html = `
        <h2 style="color:#219150">${LANG === "ar" ? "خرائط الحرارة" : "Heatmaps"}</h2>
        <div style="margin:20px 0;">
          ${LANG === "ar"
            ? "ميزة تجريبية: تفعيل أو تعطيل جمع بيانات خرائط الحرارة (heatmap) في readsb (قد تحتاج سكربت إضافي)."
            : "Experimental: Enable/disable readsb heatmap data (may need extra script support)."}
        </div>
        <div style="margin:16px 0;">
          <button class="action" onclick="enableHeatmap()">${LANG === "ar" ? "تفعيل" : "Enable"}</button>
          <button class="action" onclick="disableHeatmap()">${LANG === "ar" ? "تعطيل" : "Disable"}</button>
        </div>
    	<div id="result-heatmap"></div>
      `;
      mainContent.innerHTML = html;
    }
    function enableHeatmap() {
      callAPI('/api/service/readsb/heatmap', 'POST', {enable: true}, 'result-heatmap');
    }
    function disableHeatmap() {
      callAPI('/api/service/readsb/heatmap', 'POST', {enable: false}, 'result-heatmap');
    }

    // --- URLs Functions ---
    function renderURLs() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      mainContent.innerHTML = `<h2>Station URLs</h2>
        <div id="urls-list" style="margin-top:12px;">Loading...</div>`;
      fetch('/api/service/urls', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      })
        .then(res => res.json())
        .then(js => {
          const urlsListEl = document.getElementById("urls-list");
          if (js && js.urls && js.urls.length > 0) {
            let html = js.urls.map(
              url => `<div style="margin-bottom:9px;">
                <b>${url.title}:</b><br>
                <a href="${url.url}" target="_blank">${url.url}</a>
              </div>`
            ).join('');
            if (urlsListEl) urlsListEl.innerHTML = html;
          } else {
            if (urlsListEl) urlsListEl.innerHTML = `<span style="color:#c00">No URLs found.</span>`;
          }
        }).catch(err => {
          const urlsListEl = document.getElementById("urls-list");
          if (urlsListEl) urlsListEl.innerHTML = `<span style="color:#c00">${err.message}</span>`;
        });
    }

    // --- Support Menu Functions ---
    function renderDebug() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      mainContent.innerHTML = `<h2>${LANG === "ar" ? "نتائج التصحيح" : "Debugging Output"}</h2>
        <div id="debug-block" style="font-family: monospace; white-space: pre-wrap; background: #f0f0f0; padding: 15px; border-radius: 8px; overflow-x: auto;">Loading...</div>`;
      callAPI('/api/service/wingbits/debug', 'GET', null, 'debug-block');
    }

    function renderAllLogs() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      mainContent.innerHTML = `<h2>${LANG === "ar" ? "جميع السجلات الحديثة" : "All Recent Logs"}</h2>
        <div id="result-alllogs">Loading...</div>`;
      callAPI('/api/service/wingbits/logs', 'GET', null, 'result-alllogs');
      callAPI('/api/service/readsb/logs', 'GET', null, 'result-alllogs');
    }

    function renderLastInstallLog() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      mainContent.innerHTML = `<h2>${LANG === "ar" ? "سجل التثبيت الأخير" : "Last Install Log"}</h2>
        <div id="result-installlog">Loading...</div>`;
      callAPI('/api/service/wingbits/last-install-log', 'GET', null, 'result-installlog');
    }

    // New function to confirm client update
    function confirmUpdateClient() {
      showCustomConfirm(txt[LANG].confirm_update_client, async (confirmed) => {
        if (confirmed) {
          const mainContent = document.getElementById("main-content");
          if (!mainContent) return;

          mainContent.innerHTML = `
            <h2>${txt[LANG].update_client_progress}</h2>
            <div id="update-status-message" style="margin-bottom:15px;font-weight:bold;">${txt[LANG].update_started}</div>
            <div id="update-log-display" class="result-block" style="min-height:200px;">${txt[LANG].update_log_placeholder}</div>
            <button class="action" onclick="stopUpdatePolling()" style="margin-top:20px;" id="stop-update-btn">${LANG === 'ar' ? 'إيقاف عرض السجلات' : 'Stop Viewing Logs'}</button>
          `;
          document.getElementById('stop-update-btn').style.display = 'block'; // Show stop button

          // Initial API call to start the update
          const response = await callAPI('/api/service/wingbits/update-client', 'POST', null, null, true);
          const statusMessageEl = document.getElementById('update-status-message');
          if (response && response.ok) {
            if (statusMessageEl) statusMessageEl.style.color = 'blue';
            // Start polling for logs
            startUpdatePolling();
          } else {
            if (statusMessageEl) {
              statusMessageEl.style.color = 'red';
              statusMessageEl.innerText = response.msg || txt[LANG].update_failed;
            }
            document.getElementById('stop-update-btn').style.display = 'block'; // Allow user to dismiss
          }
        }
      });
    }

    function startUpdatePolling() {
      // Clear any existing timer first
      if (updateLogTimer) {
        clearInterval(updateLogTimer);
        updateLogTimer = null;
      }

      const logDisplayEl = document.getElementById('update-log-display');
      const statusMessageEl = document.getElementById('update-status-message');
      if (logDisplayEl) logDisplayEl.innerText = txt[LANG].fetching_logs;

      const fetchLogs = async () => {
        const response = await callAPI('/api/service/wingbits/update-logs', 'GET', null, null, true);
        if (response && response.ok) {
          if (logDisplayEl) {
            logDisplayEl.innerHTML = escapeHTML(response.logs);
            logDisplayEl.scrollTop = logDisplayEl.scrollHeight; // Auto-scroll to bottom
          }
          if (response.status === 'finished' || response.status === 'not_started') {
            stopUpdatePolling();
            if (statusMessageEl) {
                // Simple check for failure based on log content (can be improved)
                if (response.logs.includes("error") || response.logs.includes("failed") || response.logs.includes("Error:") || response.logs.includes("Failed")) { 
                    statusMessageEl.style.color = 'red';
                    statusMessageEl.innerText = txt[LANG].update_failed;
                } else {
                    statusMessageEl.style.color = 'green';
                    statusMessageEl.innerText = txt[LANG].update_finished;
                }
            }
          } else {
            if (statusMessageEl) {
              statusMessageEl.style.color = 'blue';
              statusMessageEl.innerText = txt[LANG].update_started; // Keep showing 'started' while running
            }
          }
        } else {
          stopUpdatePolling();
          if (statusMessageEl) {
            statusMessageEl.style.color = 'red';
            statusMessageEl.innerText = response.msg || txt[LANG].update_failed;
          }
        }
      };

      // Fetch immediately and then every 3 seconds
      fetchLogs();
      updateLogTimer = setInterval(fetchLogs, 3000); // Poll every 3 seconds
    }

    function stopUpdatePolling() {
      if (updateLogTimer) {
        clearInterval(updateLogTimer);
        updateLogTimer = null;
      }
      const stopBtn = document.getElementById('stop-update-btn');
      if (stopBtn) stopBtn.style.display = 'none'; // Hide stop button after stopping
    }


    function openUpdateModal() {
      let old = document.getElementById('update-modal');
      if (old) old.remove();

      const modal = document.createElement('div');
      modal.id = 'update-modal';
      modal.style = "display:flex;position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:3000;background:rgba(0,0,0,0.33);justify-content:center;align-items:center;";
      modal.innerHTML = `
        <div style="background:#fff;max-width:370px;width:95vw;padding:26px 20px 20px 20px;border-radius:12px;box-shadow:0 3px 18px #0003;position:relative">
          <h3 style="margin-bottom:16px;text-align:${LANG==='ar'?'right':'left'}">${LANG==="ar"?"تحديث أو إعادة تثبيت المكونات":"Update/Reinstall Components"}</h3>
          <div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;direction:ltr;">
              <input type="checkbox" id="comp_wingbits" checked style="width:18px;height:18px;">
              <label for="comp_wingbits" style="font-size:1.12em;min-width:110px;cursor:pointer">${LANG==="ar"?"عميل Wingbits":"Wingbits Client"}</label>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;direction:ltr;">
              <input type="checkbox" id="comp_readsb" checked style="width:18px;height:18px;">
              <label for="comp_readsb" style="font-size:1.12em;min-width:110px;cursor:pointer">readsb</label>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;direction:ltr;">
              <input type="checkbox" id="comp_tar1090" checked style="width:18px;height:18px;">
              <label for="comp_tar1090" style="font-size:1.12em;min-width:110px;cursor:pointer">tar1090</label>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;direction:ltr;">
              <input type="checkbox" id="comp_panel" style="width:18px;height:18px;">
              <label for="comp_panel" style="font-size:1.12em;min-width:110px;cursor:pointer">${LANG==="ar"?"لوحة التحكم":"Web Panel"}</label>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;direction:ltr;">
              <input type="checkbox" id="comp_deps" style="width:18px;height:18px;">
              <label for="comp_deps" style="font-size:1.12em;min-width:110px;cursor:pointer">${LANG==="ar"?"الاعتماديات (python, rtl-sdr)":"Dependencies (python, rtl-sdr)"}</label>
            </div>
          </div>
          <div id="update-modal-status" style="margin:14px 0 8px 0; color:#1560db;"></div>
          <div style="text-align:right;margin-top:12px">
            <button onclick="doUpdateReinstall()" style="padding:6px 18px">${LANG==="ar"?"تأكيد":"Confirm"}</button>
            <button onclick="closeUpdateModal()" style="padding:6px 18px">${LANG==="ar"?"إغلاق":"Close"}</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }

    function closeUpdateModal() {
      let modal = document.getElementById('update-modal');
      if (modal) modal.remove();
    }

    function doUpdateReinstall() {
      const comps = [];
      if(document.getElementById("comp_wingbits").checked) comps.push("wingbits");
      if(document.getElementById("comp_readsb").checked) comps.push("readsb");
      if(document.getElementById("comp_tar1090").checked) comps.push("tar1090");
      if(document.getElementById("comp_panel").checked) comps.push("panel");
      if(document.getElementById("comp_deps").checked) comps.push("deps");

      if(comps.length === 0) {
        document.getElementById("update-modal-status").style.color = "red";
        document.getElementById("update-modal-status").innerText = LANG==="ar"?"اختر مكون واحد على الأقل!":"Please select at least one component!";
        return;
      }
      document.getElementById("update-modal-status").style.color = "#1560db";
      document.getElementById("update-modal-status").innerText = LANG==="ar"?"جاري التنفيذ...":"Running, please wait...";
      fetch('/api/update/reinstall', {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
            'X-Auth-Token': AUTH_TOKEN
        },
        body: JSON.stringify({components: comps})
      }).then(res=>res.json()).then(js=>{
        if(js.ok) {
          document.getElementById("update-modal-status").style.color = "green";
          document.getElementById("update-modal-status").innerText = (js.msg || (LANG==="ar"?"تم التنفيذ!":"Done!")) + "\n" + (js.detail||"");
        } else {
          document.getElementById("update-modal-status").style.color = "red";
          document.getElementById("update-modal-status").innerText = (js.msg||"Unknown error");
        }
      }).catch(()=>{
        document.getElementById("update-modal-status").style.color = "red";
        document.getElementById("update-modal-status").innerText = LANG==="ar"?"خطأ في الاتصال!":"Network error!";
      });
    }

    function loadFeederVersions() {
      console.log("loadFeederVersions called");
      const block = document.getElementById("feeder-versions-block");
      if (!block) return; // Defensive check
      block.innerHTML = (LANG === "ar" ? "جاري التحميل..." : "Loading...");
      fetch('/api/feeder/versions', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      }).then(res => res.json()).then(js => {
        if (js && js.ok && js.versions) {
          const v = js.versions;
          block.innerHTML = `
            <div style="font-size:1em">
              <b>Wingbits:</b> ${v.wingbits || '-'}<br>
              <b>readsb:</b> ${v.readsb || '-'}<br>
              <b>tar1090:</b> ${v.tar1090 || '-'}<br>
              <b>${LANG === "ar" ? "لوحة التحكم" : "Web Panel"}:</b> ${v.panel || '-'}<br>
            </div>
            <div style="color:#666;font-size:0.92em;margin-top:4px">
              ${LANG === "ar" ? "آخر تحديث:" : "Checked at:"} ${js.checked_at || "-"}
            </div>
          `;
        } else {
          block.innerHTML = `<span style="color:red">${(js && js.msg) ? js.msg : (LANG === "ar" ? "تعذر جلب الإصدارات" : "Failed to load versions")}</span>`;
        }
      }).catch(e => {
        block.innerHTML = `<span style="color:red">${LANG === "ar" ? "خطأ في الشبكة!" : "Network error!"}</span>`;
      });
    }

    function loadStatusBlock() {
      const block = document.getElementById("status-block");
      if (!block) return; // Defensive check
      block.innerHTML = (LANG === "ar" ? "جاري الفحص..." : "Checking...");
      fetch('/api/status/check', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      }).then(res=>res.json()).then(js=>{
        if(js && js.ok && js.status) {
          const s = js.status;
          let html = `
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px 22px;font-size:1em;margin-bottom:12px">
              <div>${LANG==="ar"?"الإنترنت":"Internet"}</div>
              <div>${s.internet?'<span style="color:green">&#10004;</span>':'<span style="color:red">&#10008;</span>'}</div>
              <div>Wingbits</div>
              <div>${s.wingbits?'<span style="color:green">&#10004;</span>':'<span style="color:red">&#10008;</span>'}</div>
              <div>readsb</div>
              <div>${s.readsb?'<span style="color:green">&#10004;</span>':'<span style="color:red">&#10008;</span>'}</div>
              <div>tar1090</div>
              <div>${s.tar1090?'<span style="color:green">&#10004;</span>':'<span style="color:red">&#10008;</span>'}</div>
            </div>
          `;

          if(s.wb_details) {
            let lines = s.wb_details.split('\n')
              .filter(line => line.trim() && !/^Wingbits version/i.test(line));
            html += `<div style="background:#f7f7fa;padding:10px 16px;border-radius:7px;border:1px solid #eee;font-size:1em">`;
            lines.forEach(line => {
              let color = line.includes("OK") || line.includes("✓") ? "green"
                : (line.includes("fail") || line.includes("not") || line.includes("Error") || line.includes("✗")) ? "red" : "#333";
              html += `<div style="color:${color}">${line.replace("✓", "&#10004;").replace("✗", "&#10008;")}</div>`;
            });
            html += `</div>`;
          }
          block.innerHTML = html;
        } else {
          block.innerHTML = `<div style="color:red">${LANG === "ar" ? "فشل جلب الحالة" : "Failed to fetch status"}</div>`;
        }
      }).catch(e=>{
        block.innerHTML = `<span style="color:red">${LANG === "ar" ? "خطأ في الاتصال" : "Network error"}</span>`;
      });
    }

    function loadAlerts() {
      const block = document.getElementById("alerts-content");
      if (!block) return; // Defensive check
      block.innerHTML = `<div style="padding:32px;text-align:center;color:#888;font-size:1.1em">${LANG==="ar"?"جاري البحث عن تنبيهات...":"Checking for alerts..."}</div>`;
      fetch('/api/alerts', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      }).then(res=>res.json()).then(js=>{
        if(js && js.ok) {
          if(js.alerts && js.alerts.length) {
            block.innerHTML = js.alerts.map(a=>`
              <div style="background:#fff3f3;border:1px solid #e7b1b1;color:#c70a0a;border-radius:7px;margin-bottom:12px;padding:12px 17px;font-size:1.1em;">
                <span style="font-family:monospace">${a}</span>
              </div>
            `).join('');
          } else {
            block.innerHTML = `<div style="padding:28px;text-align:center;color:green;font-size:1.13em">${LANG==="ar"?"لا توجد أخطاء أو تحذيرات نشطة":"No active alerts."}</div>`;
          }
        } else {
          block.innerHTML = `<div style="padding:20px;color:red">${LANG==="ar"?"فشل تحميل التنبيهات":"Failed to load alerts."}</div>`;
        }
      }).catch(e=>{
        block.innerHTML = `<div style="padding:20px;color:red">${LANG==="ar"?"خطأ بالشبكة":"Network error."}</div>`;
      });
    }

    function updateSystemInfoBlock() {
      fetch('/api/system/info', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      }).then(res=>res.json()).then(js=>{
        const systemInfoBlockEl = document.getElementById("system-info-block");
        if (js && js.ok) {
          const d = js.info;
          if (systemInfoBlockEl) { // Check if element exists
            systemInfoBlockEl.innerHTML = `
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.3em 1.7em">
            <div>${LANG==="ar" ? "اسم المضيف" : "Hostname"}</div><div><b>${d.hostname}</b></div>
            <div>${LANG==="ar" ? "النظام" : "OS"}</div><div><b>${d.os}</b></div>
            <div>${LANG==="ar" ? "المعالج" : "CPU"}</div><div><b>${d.cpu}</b></div>
            <div>${LANG==="ar" ? "عدد الأنوية" : "Cores"}</div><div><b>${d.cores}</b></div>
            <div>${LANG==="ar" ? "المعمارية" : "Arch"}</div><div><b>${d.arch}</b></div>
            <div>${LANG==="ar" ? "متوسط التحميل" : "Load Avg"}</div><div><b>${d.load_avg ? d.load_avg.map(x=>x.toFixed(2)).join(' / ') : "-"}</b></div>
            <div>${LANG==="ar" ? "الرام الكلي (MB)" : "Total RAM (MB)"}</div><div><b>${d.ram_total_mb}</b></div>
            <div>${LANG==="ar" ? "الرام المتاح (MB)" : "Free RAM (MB)"}</div><div><b>${d.ram_free_mb}</b></div>
            <div>${LANG==="ar" ? "الهارد الكلي (GB)" : "Disk total (GB)"}</div><div><b>${d.disk_total_gb}</b></div>
            <div>${LANG==="ar" ? "الهارد المتاح (GB)" : "Disk free (GB)"}</div><div><b>${d.disk_free_gb}</b></div>
            <div>${LANG==="ar" ? "مدة التشغيل (ساعة)" : "Uptime (hours)"}</div><div><b>${d.uptime_hr}</b></div>
            <div>${LANG==="ar" ? "درجة حرارة المعالج" : "CPU Temp (°C)"}</div><div><b>${d.cpu_temp ?? "-"}</b></div>
            <div>${LANG==="ar" ? "حالة SDR" : "SDR Dongle"}</div>
            <div><b>${
              d.sdr_status === "connected"
              ? (LANG === "ar" ? "متصل" : "Connected")
              : (LANG === "ar" ? "غير متصل" : "Not Connected")
            }</b></div>
    		<div><b>
    		</b></div>
    		<div><b>
    		</b></div>
          </div>
          `;
          }
        } else {
          if (systemInfoBlockEl) { // Check if element exists
            systemInfoBlockEl.innerHTML = `<div style="color:red">Error: ${js.msg || "unknown error"}</div>`;
          }
        }
      });
    }

    function updateNetStatusBlock() {
      fetch('/api/netstatus', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      }).then(res=>res.json()).then(js=>{
        const netstatusBlockEl = document.getElementById("netstatus-block");
        if(js && js.ok) {
          const d = js.net;
          let txtConn = (LANG==="ar" ? 
            (d.online ? "متصل بالإنترنت" : "غير متصل بالإنترنت") :
            (d.online ? "Internet: Connected" : "Internet: Not connected"));
          let txtSrv = (LANG==="ar" ?
            (d.server_ok ? "متصل بسيرفر Wingbits" : "تعذر الاتصال بسيرفر Wingbits") :
            (d.server_ok ? "Wingbits server: Connected" : "Wingbits server: Not reachable"));
          let txtLast = d.last_sync ?
            ((LANG==="ar" ? "آخر مزامنة:" : "Last Sync:") + " <b>" + d.last_sync + "</b>") : "";

          if (netstatusBlockEl) { // Check if element exists
            netstatusBlockEl.innerHTML = `
            <div style="color:${d.online ? "#197b1f":"#b80c09"};font-weight:bold;margin-bottom:2px">${txtConn}</div>
            <div style="color:${d.server_ok ? "#1355c2":"#bb0d27"};font-weight:bold;margin-bottom:2px">${txtSrv}</div>
            <div style="color:#5c5c5c;font-size:0.98em">${txtLast}</div>
            `;
          }
        } else {
          if (netstatusBlockEl) { // Check if element exists
            netstatusBlockEl.innerHTML = `<span style="color:red">${LANG==="ar"?"خطأ":"Error"}</span>`;
          }
        }
      }).catch(e=>{
        const netstatusBlockEl = document.getElementById("netstatus-block");
        if (netstatusBlockEl) { // Check if element exists
          netstatusBlockEl.innerHTML = `<span style="color:red">${LANG==="ar"?"خطأ بالشبكة":"Network Error"}</span>`;
        }
      });
    }

    function copyDebugInfo() {
      const statusEl = document.getElementById("copy-debug-info-status");
      if (!statusEl) return; // Defensive check
      statusEl.style.color = "black";
      statusEl.innerText = LANG === "ar" ? "جاري التجميع..." : "Gathering info...";
      fetch('/api/debug/info', {
        headers: { 'X-Auth-Token': AUTH_TOKEN }
      }).then(res => {
        if (!res.ok) throw new Error("Network response was not ok");
        return res.json();
      }).then(js => {
        if(js && js.ok && js.info) {
          const d = js.info;
          let infoText =
`Station Debug Info
----------------------------------------
ID: ${d.station_id || "-"}
Host: ${d.hostname || "-"}
IP: ${d.ip || "-"}
Location: ${d.lat || "-"},${d.lon || "-"}
Wingbits: ${d.wingbits_ver || "-"}
readsb: ${d.readsb_ver || "-"}
tar1090: ${d.tar1090_ver || "-"}
Recent Logs:
${d.logs || "-"}
`;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(infoText).then(() => {
              statusEl.style.color = "green";
              statusEl.innerText = LANG === "ar" ? "تم نسخ بيانات التشخيص!" : "Debug info copied!";
              setTimeout(() => statusEl.innerText = "", 3000);
            }).catch(err => {
              statusEl.style.color = "red";
              statusEl.innerText = (LANG === "ar" ? "فشل النسخ: " : "Copy failed: ") + err;
            });
          } else {
            let textarea = document.createElement('textarea');
            textarea.value = infoText;
            document.body.appendChild(textarea);
            textarea.select();
            try {
              document.execCommand('copy');
              statusEl.style.color = "green";
              statusEl.innerText = LANG === "ar" ? "تم النسخ يدويًا!" : "Copied manually!";
            } catch (e) {
              statusEl.style.color = "red";
              statusEl.innerText = LANG === "ar" ? "فشل النسخ اليدوي!" : "Manual copy failed!";
            }
            document.body.removeChild(textarea);
          }
        } else {
          statusEl.style.color = "red";
          statusEl.innerText = (js && js.msg) ? js.msg : (LANG === "ar" ? "خطأ غير معروف!" : "Unknown error!");
        }
      }).catch(err => {
        statusEl.style.color = "red";
        statusEl.innerText = (LANG === "ar" ? "Network error: " : "Network error: ") + err;
      });
    }

    // --- Restart / Shutdown Functions ---
    function renderPower() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      let html = `
        <h2>${LANG === "ar" ? "إعادة تشغيل الخدمات / الجهاز" : "Restart / Shutdown"}</h2>
        <div class="result-block" style="margin-bottom:18px;">
          <b>wingbits restart</b><br>
          Restart the wingbits service<br>
          <button class="action" onclick="callAPI('/api/service/wingbits/restart','POST',null,'result-wingbits-restart')">${LANG === "ar" ? "إعادة تشغيل" : "Restart"}</button>
          <div id="result-wingbits-restart"></div>
          <hr/>
          <b>readsb restart</b><br>
          Restart the readsb service<br>
          <button class="action" onclick="callAPI('/api/service/readsb/restart','POST',null,'result-readsb-restart')">${LANG === "ar" ? "إعادة تشغيل" : "Restart"}</button>
          <div id="result-readsb-restart"></div>
          <hr/>
          <b>tar1090 restart</b><br>
          Restart tar1090 service<br>
          <button class="action" onclick="callAPI('/api/service/tar1090/restart','POST',null,'result-tar1090-restart')">${LANG === "ar" ? "إعادة تشغيل" : "Restart"}</button>
          <div id="result-tar1090-restart"></div>
          <hr/>
          <b>Device restart</b><br>
          Restart the Wingbits Station<br>
          <button class="action" style="background:#d35400" onclick="confirmReboot()">${LANG === "ar" ? "إعادة تشغيل الجهاز" : "Restart Device"}</button>
          <div id="result-pi-reboot"></div>
          <hr/>
          <b>SHUTDOWN device</b><br>
          Shutdown the Wingbits Station<br>
          <button class="action" style="background:#e74c3c" onclick="confirmShutdown()">${LANG === "ar" ? "إيقاف التشغيل" : "Shutdown Device"}</button>
          <div id="result-pi-shutdown"></div>
        </div>
      `;
      mainContent.innerHTML = html;
    }

    function confirmReboot() {
      showCustomConfirm(LANG === "ar" ? "سيتم إعادة تشغيل الجهاز!" : "Device will reboot!", (confirmed) => {
        if (confirmed) {
          callAPI('/api/system/reboot', 'POST', null, 'result-pi-reboot');
        }
      });
    }
    function confirmShutdown() {
      showCustomConfirm(LANG === "ar" ? "سيتم إيقاف تشغيل الجهاز!" : "Device will shutdown!", (confirmed) => {
        if (confirmed) {
          callAPI('/api/system/shutdown', 'POST', null, 'result-pi-shutdown');
        }
      });
    }

    // --- Diagnostics Page Functions ---
    function renderDiagnosticsPage() {
        const mainContent = document.getElementById("main-content");
        if (!mainContent) return;
        mainContent.innerHTML = `
            <h2>${txt[LANG].diagnostics_title}</h2>
            
            <div class="diagnostics-section">
                <h3>${txt[LANG].generate_log_url_title}</h3>
                <p>${txt[LANG].generate_log_url_desc}</p>
                <button class="action" onclick="generateLogLink('wingbits_readsb', 'log-link-result-1')">${txt[LANG].generate_wingbits_readsb_link}</button>
                <div id="log-link-result-1"></div>
                <button class="action" onclick="generateLogLink('all', 'log-link-result-2')">${txt[LANG].generate_all_logs_link}</button>
                <div id="log-link-result-2"></div>
            </div>

            <div class="diagnostics-section">
                <h3>${txt[LANG].handy_commands_title}</h3>
                <div class="diag-command-item">
                    <button class="action" onclick="runDiagnosticCommand('os_release', 'diag-result-os')">${txt[LANG].view_os_release}</button>
                    <div id="diag-result-os"></div>
                </div>
                <div class="diag-command-item">
                    <button class="action" onclick="runDiagnosticCommand('lsusb', 'diag-result-lsusb')">${txt[LANG].view_usb_devices}</button>
                    <div id="diag-result-lsusb"></div>
                </div>
                <div class="diag-command-item">
                    <button class="action" onclick="runDiagnosticCommand('throttled', 'diag-result-throttled')">${txt[LANG].check_voltage} (Pi only)</button>
                    <div id="diag-result-throttled"></div>
                </div>
                <div class="diag-command-item">
                    <button class="action" onclick="runDiagnosticCommand('wingbits_status_verbose', 'diag-result-wb-status')">${txt[LANG].view_wingbits_status_verbose}</button>
                    <div id="diag-result-wb-status"></div>
                </div>
                <div class="diag-command-item">
                    <button class="action" onclick="runDiagnosticCommand('geosigner_info', 'diag-result-geo')">${txt[LANG].view_geosigner_info}</button>
                    <div id="diag-result-geo"></div>
                </div>
            </div>
        `;
    }

    function generateLogLink(logType, resultId) {
        const resultElement = document.getElementById(resultId);
        if (resultElement) {
            resultElement.innerHTML = `<div class="log-link-result" style="color:#888; padding: 10px;">${txt[LANG].please_wait}</div>`;
        }
        callAPI('/api/diagnostics/generate-log-link', 'POST', { type: logType }, null, true)
            .then(data => {
                if (resultElement) {
                    if (data && data.ok && data.result.startsWith('http')) {
                        const uniqueInputId = `log-url-${resultId}`;
                        resultElement.innerHTML = `
                            <div style="display: flex; align-items: center; gap: 10px; margin-top: 10px;">
                                <input type="text" id="${uniqueInputId}" value="${escapeHTML(data.result)}" readonly style="flex-grow: 1; background-color: #e9f5ff; border: 1px solid #b3d7ff; color: #333;">
                                <button class="action" onclick="copyToClipboard('${uniqueInputId}', this)" style="width: auto; padding: 10px 15px; margin-top: 0;">${txt[LANG].copy_link}</button>
                            </div>
                        `;
                    } else {
                        resultElement.innerHTML = `<div class="log-link-result" style="color:red;">Error: ${data.msg || data.result || 'Failed to generate link.'}</div>`;
                    }
                }
            });
    }
    
    function copyToClipboard(elementId, buttonElement) {
        const input = document.getElementById(elementId);
        if (input) {
            input.select();
            input.setSelectionRange(0, 99999); // For mobile devices
            try {
                // Use the modern clipboard API if available, with a fallback
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(input.value);
                } else {
                    document.execCommand('copy');
                }
                
                if(buttonElement) {
                    const oldText = buttonElement.innerText;
                    buttonElement.innerText = txt[LANG].copied;
                    buttonElement.disabled = true;
                    setTimeout(() => { 
                        buttonElement.innerText = oldText; 
                        buttonElement.disabled = false;
                    }, 2000);
                }
            } catch (err) {
                showCustomAlert('Failed to copy: ' + err);
            }
        }
    }


    function runDiagnosticCommand(commandKey, resultId) {
        callAPI('/api/diagnostics/run-command', 'POST', { command: commandKey }, resultId);
    }


    // --- Help / About Page Functions ---
    function renderHelp() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      let html = `<h2>${txt[LANG].about}</h2>
        <div style="margin:10px 0;">
          <b>Wingbits Station Web Config</b><br/>
          ${LANG === "ar" ? "لوحة تحكم مبنية باستخدام بايثون وHTML لسهولة إدارة محطة التتبع." : "A simple Python+HTML dashboard for easy station management."}
          <br/><br/>
          </div>
        <div style="margin:14px 0 0 0;font-size:0.98em;color:#888;">by Said Albalushi</div>
        <div id="result-block"></div>
      `;
      mainContent.innerHTML = html;
    }

    // --- Authentication Pages and Functions ---
    function renderLoginPage() {
      // Clear any active chart/timers before rendering login page
      if (liveChart) {
        liveChart.destroy();
        liveChart = null;
      }
      if (liveTimer) {
        clearInterval(liveTimer);
        liveTimer = null;
      }
      if (updateLogTimer) { // Clear update log timer
        clearInterval(updateLogTimer);
        updateLogTimer = null;
      }


      const container = document.getElementById("container");
      if (!container) {
        console.error("Container element not found for login page.");
        return;
      }
      container.innerHTML = `
        <div class="login-container" id="login-container">
          <div class="login-box">
            <h2>${txt[LANG].login}</h2>
            <input type="text" id="username" placeholder="${txt[LANG].username}" />
            <input type="password" id="password" placeholder="${txt[LANG].password}" />
            <button class="action" onclick="loginUser()">${txt[LANG].login}</button>
            <div id="login-message" class="login-message"></div>
          </div>
        </div>
      `;
      document.body.classList.remove('rtl'); // Ensure no RTL on login page
      document.body.dir = 'ltr';

      // Add event listener for Enter key on password field
      const passwordInput = document.getElementById('password');
      if (passwordInput) {
        passwordInput.addEventListener('keydown', function(event) {
          if (event.key === 'Enter' || event.keyCode === 13) {
            event.preventDefault(); // Prevent default form submission
            loginUser();
          }
        });
      }
    }

    async function loginUser() {
      const usernameInput = document.getElementById('username');
      const passwordInput = document.getElementById('password');
      const loginMessage = document.getElementById('login-message');

      if (!usernameInput || !passwordInput || !loginMessage) {
        console.error("Login page elements not found.");
        return;
      }

      const username = usernameInput.value;
      const password = passwordInput.value;
      loginMessage.innerText = txt[LANG].please_wait;
      loginMessage.style.color = '#888';

      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (data.ok) {
          AUTH_TOKEN = data.token;
          localStorage.setItem('auth_token', AUTH_TOKEN);
          loginMessage.innerText = '';
          checkAuthAndRender(); // Redirect to main content
        } else {
          loginMessage.style.color = 'red';
          loginMessage.innerText = data.msg || txt[LANG].login_failed;
        }
      } catch (error) {
        loginMessage.style.color = 'red';
        loginMessage.innerText = 'Network error during login.';
        console.error('Login error:', error);
      }
    }

    async function logoutUser() {
      showCustomConfirm(LANG === "ar" ? "هل أنت متأكد من تسجيل الخروج؟" : "Are you sure you want to log out?", async (confirmed) => {
        if (confirmed) {
          try {
            const response = await fetch('/api/logout', {
              method: 'POST',
              headers: { 'X-Auth-Token': AUTH_TOKEN }
            });
            const data = await response.json();

            if (data.ok) {
              AUTH_TOKEN = null;
              localStorage.removeItem('auth_token');
              // Clear any active chart/timers before rendering login page
              if (liveChart) {
                liveChart.destroy();
                liveChart = null;
              }
              if (liveTimer) {
                clearInterval(liveTimer);
                liveTimer = null;
              }
              if (updateLogTimer) { // Clear update log timer
                clearInterval(updateLogTimer);
                updateLogTimer = null;
              }
              checkAuthAndRender(); // Redirect to login page
            } else {
              showCustomAlert(data.msg || "Logout failed.");
            }
          } catch (error) {
            showCustomAlert("Network error during logout.");
            console.error('Logout error:', error);
          }
        }
      });
    }

    function renderChangePasswordPage() {
      const mainContent = document.getElementById("main-content");
      if (!mainContent) return; // Defensive check
      mainContent.innerHTML = `
        <h2>${txt[LANG].change_password}</h2>
        <div class="form-group">
          <label for="old_password">${txt[LANG].old_password}</label>
          <input type="password" id="old_password" />
        </div>
        <div class="form-group">
          <label for="new_password">${txt[LANG].new_password}</label>
          <input type="password" id="new_password" />
        </div>
        <div class="form-group">
          <label for="confirm_new_password">${txt[LANG].confirm_new_password}</label>
          <input type="password" id="confirm_new_password" />
        </div>
        <button class="action" onclick="changePassword()">${txt[LANG].update_password}</button>
        <div id="password-change-message" class="login-message"></div>
      `;
    }

    async function changePassword() {
      const oldPasswordInput = document.getElementById('old_password');
      const newPasswordInput = document.getElementById('new_password');
      const confirmNewPasswordInput = document.getElementById('confirm_new_password');
      const messageDiv = document.getElementById('password-change-message');

      if (!oldPasswordInput || !newPasswordInput || !confirmNewPasswordInput || !messageDiv) {
        console.error("Password change page elements not found.");
        return;
      }

      const oldPassword = oldPasswordInput.value;
      const newPassword = newPasswordInput.value;
      const confirmNewPassword = confirmNewPasswordInput.value;

      if (newPassword !== confirmNewPassword) {
        messageDiv.style.color = 'red';
        messageDiv.innerText = txt[LANG].password_mismatch;
        return;
      }
      if (newPassword.length < 6) {
        messageDiv.style.color = 'red';
        messageDiv.innerText = txt[LANG].password_too_short;
        return;
      }

      messageDiv.innerText = txt[LANG].please_wait;
      messageDiv.style.color = '#888';

      try {
        const response = await fetch('/api/change_password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Auth-Token': AUTH_TOKEN
          },
          body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
        });
        const data = await response.json();

        if (data.ok) {
          messageDiv.style.color = 'green';
          messageDiv.innerText = txt[LANG].password_changed_success;
          AUTH_TOKEN = null; // Invalidate token on successful password change
          localStorage.removeItem('auth_token');
          // Clear any active chart/timers before rendering login page
          if (liveChart) {
            liveChart.destroy();
            liveChart = null;
          }
          if (liveTimer) {
            clearInterval(liveTimer);
            liveTimer = null;
          }
          if (updateLogTimer) { // Clear update log timer
            clearInterval(updateLogTimer);
            updateLogTimer = null;
          }
          setTimeout(checkAuthAndRender, 2000); // Redirect to login after 2 seconds
        } else {
          messageDiv.style.color = 'red';
          messageDiv.innerText = data.msg || txt[LANG].password_change_fail;
        }
      } catch (error) {
        messageDiv.style.color = 'red';
        messageDiv.innerText = 'Network error during password change.';
        console.error('Password change error:', error);
      }
    }

    // --- General Utility Functions ---
    function showModal(title, content) {
      let m = document.createElement("div");
      m.style = "position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:999;background:rgba(0,0,0,0.4);display:flex;align-items:center;justify-content:center";
      m.innerHTML = `<div style="background:#fff;padding:16px 22px;min-width:280px;max-width:96vw;max-height:85vh;overflow:auto;border-radius:12px;box-shadow:0 6px 32px #0003">
        <div style="font-weight:bold;font-size:1.2em;margin-bottom:10px">${title}</div>
        ${content}
        <div style="text-align:center;margin-top:12px"><button onclick="this.parentNode.parentNode.parentNode.remove()">OK</button></div>
      </div>`;
      document.body.appendChild(m);
    }

    function showCustomConfirm(message, callback) {
      const modalId = 'custom-confirm-modal';
      let oldModal = document.getElementById(modalId);
      if (oldModal) oldModal.remove();

      const modal = document.createElement('div');
      modal.id = modalId;
      modal.style = "display:flex;position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:3000;background:rgba(0,0,0,0.33);justify-content:center;align-items:center;";
      modal.innerHTML = `
        <div style="background:#fff;max-width:370px;width:95vw;padding:26px 20px 20px 20px;border-radius:12px;box-shadow:0 3px 18px #0003;position:relative">
          <p style="margin-bottom:20px;font-size:1.1em;text-align:center;">${message}</p>
          <div style="text-align:center;">
            <button id="confirm-yes-btn" class="action" style="background:#28a745; margin-right: 10px;">${LANG === "ar" ? "نعم" : "Yes"}</button>
            <button id="confirm-no-btn" class="action" style="background:#dc3545;">${LANG === "ar" ? "لا" : "No"}</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);

      const yesBtn = document.getElementById('confirm-yes-btn');
      const noBtn = document.getElementById('confirm-no-btn');

      if (yesBtn) {
        yesBtn.addEventListener('click', () => {
          modal.remove();
          if (callback) callback(true);
        });
      }
      if (noBtn) {
        noBtn.addEventListener('click', () => {
          modal.remove();
          if (callback) callback(false);
        });
      }
    }

    function showCustomAlert(message) {
      const modalId = 'custom-alert-modal';
      let oldModal = document.getElementById(modalId);
      if (oldModal) oldModal.remove();

      const modal = document.createElement('div');
      modal.id = modalId;
      modal.style = "display:flex;position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:3000;background:rgba(0,0,0,0.33);justify-content:center;align-items:center;";
      modal.innerHTML = `
        <div style="background:#fff;max-width:370px;width:95vw;padding:26px 20px 20px 20px;border-radius:12px;box-shadow:0 3px 18px #0003;position:relative">
          <p style="margin-bottom:20px;font-size:1.1em;text-align:center;">${message}</p>
          <div style="text-align:center;">
            <button class="action" onclick="document.getElementById('${modalId}').remove();">${LANG === "ar" ? "موافق" : "OK"}</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }

    function escapeHTML(txt) {
      return (""+txt).replace(/[<>&"]/g, function(c) {
        return {'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c];
      });
    }

    // --- API Communication with Backend ---
    async function callAPI(url, method = 'GET', data = null, resultId = "result-block", returnPromise = false) {
      const resultElement = document.getElementById(resultId);
      if(resultId && resultElement) {
        resultElement.innerHTML = `<span style="color:#888">${txt[LANG].please_wait}</span>`;
      }
      let opts = {method: method};
      opts.headers = { 'Content-Type': 'application/json' };
      if (AUTH_TOKEN) {
        opts.headers['X-Auth-Token'] = AUTH_TOKEN;
      }
      if(data) opts.body = JSON.stringify(data);
      try {
        let q = url.includes("?") ? "&" : "?";
        let res = await fetch(url + q + "lang=" + LANG, opts);

        if (res.status === 401) { // Unauthorized
            AUTH_TOKEN = null;
            localStorage.removeItem('auth_token');
            checkAuthAndRender(); // Redirect to login page
            return null;
        }

        let js = await res.json();

        let result = js.result || js.msg || js.ok || "";
        let desc = js.desc ? `<div class="desc-block">${js.desc}</div>` : "";
        if(resultId && resultElement) {
          resultElement.innerHTML =
            desc + (result ? `<div class="result-block">${escapeHTML(result)}</div>` : "");
        }
        if (returnPromise) return js;
      } catch (e) {
        if(resultId && resultElement) {
          resultElement.innerHTML = `<div style="color:#e74c3c">${e.message}</div>`;
        }
        if (returnPromise) return null;
      }
    }

    // --- Authentication Check and Page Rendering ---
    async function checkAuthAndRender() {
        AUTH_TOKEN = localStorage.getItem('auth_token');
        let sidebar = document.getElementById('sidebar');
        let logoutBtn = document.getElementById('logout-btn');
        const container = document.getElementById('container'); 

        if (!AUTH_TOKEN) {
            // Clear any active chart/timers before rendering login page
            if (liveChart) {
                liveChart.destroy();
                liveChart = null;
            }
            if (liveTimer) {
                clearInterval(liveTimer);
                liveTimer = null;
            }
            if (updateLogTimer) { // Clear update log timer
                clearInterval(updateLogTimer);
                updateLogTimer = null;
            }
            if (sidebar) sidebar.style.display = 'none';
            if (logoutBtn) logoutBtn.style.display = 'none';
            renderLoginPage();
            return;
        }

        // Verify token with a simple API call (e.g., to /api/system/info)
        try {
            const response = await fetch('/api/system/info', {
                headers: { 'X-Auth-Token': AUTH_TOKEN }
            });
            if (response.status === 401) {
                AUTH_TOKEN = null;
                localStorage.removeItem('auth_token');
                // Clear any active chart/timers before rendering login page
                if (liveChart) {
                    liveChart.destroy();
                    liveChart = null;
                }
                if (liveTimer) {
                    clearInterval(liveTimer);
                    liveTimer = null;
                }
                if (updateLogTimer) { // Clear update log timer
                    clearInterval(updateLogTimer);
                    updateLogTimer = null;
                }
                if (sidebar) sidebar.style.display = 'none';
                if (logoutBtn) logoutBtn.style.display = 'none';
                renderLoginPage();
                return;
            }
            
            // If authenticated, ensure the main application structure is present
            // and then show sidebar and render content.
            if (!document.getElementById('side-menu') || !document.getElementById('main-content')) { 
                // Rebuild the entire container content if it was replaced by login page
                container.innerHTML = `
                    <div class="sidebar" id="sidebar">
                        <img class="logo" src="https://wingbits.com/apple-icon.png?34e8dd62bf865c3e" alt="Wingbits" />
                        <div class="side-title" id="side-title">Wingbits Web Config</div>
                        <div class="side-menu" id="side-menu"></div>
                        <div class="lang-switch">
                            <button id="en-btn" class="active" onclick="setLang('en')">EN</button>
                            <button id="ar-btn" class="active" onclick="setLang('ar')">العربية</button>
                        </div>
                        <button class="action" style="margin-top: auto; margin-bottom: 15px; width: 80%;" onclick="logoutUser()" id="logout-btn"></button>
                    </div>
                    <div class="main" id="main-content"></div>
                `;
                // Re-get references to newly created elements
                sidebar = document.getElementById('sidebar'); // Re-assign sidebar
                logoutBtn = document.getElementById('logout-btn'); // Re-assign logoutBtn
            } 
            
            // Ensure visibility after successful authentication
            if (sidebar) sidebar.style.display = 'flex';
            if (logoutBtn) logoutBtn.style.display = 'block';

            setLang(LANG); // Re-render menu with correct language
            renderMenuPage('live_stats'); // Render default page after login
        } catch (error) {
            console.error('Authentication check failed:', error);
            // If network error or other issue, revert to login page
            // Clear any active chart/timers before rendering login page
            if (liveChart) {
                liveChart.destroy();
                liveChart = null;
            }
            if (liveTimer) {
                clearInterval(liveTimer);
                liveTimer = null;
            }
            if (updateLogTimer) { // Clear update log timer
                clearInterval(updateLogTimer);
                updateLogTimer = null;
            }
            if (sidebar) sidebar.style.display = 'none';
            if (logoutBtn) logoutBtn.style.display = 'none';
            renderLoginPage();
            const loginMessage = document.getElementById('login-message');
            if (loginMessage) {
              loginMessage.innerText = 'Network error during authentication check. Please try again.';
              loginMessage.style.color = 'red';
            }
        }
    }

    // --- Page Initialization ---
    // Moved window.onload to the very end of the script block
    window.onload = function() {
      checkAuthAndRender();
    }
  </script>
</body>
</html>
EOF

echo "Frontend files written."
echo