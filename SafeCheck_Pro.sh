#!/bin/bash
set -euo pipefail

# ───────────────────────────────────────────────
# SafeCheck_Pro.sh — OGF/Poseidon macOS quick scan (recursive + OGF in dirs)
# Credits: Khalid | Routers.world | Tw: @REMiX_KSA
# ───────────────────────────────────────────────

# ===== Config =====
SCAN_DIRS=("$HOME/Downloads" "$HOME/Desktop")  # recursive scan
CHECK_MOUNTED_VOLUMES=true
RUN_BROKENSTONES_SCRIPT=true
CHECK_RENTRY_IPS=true
AUTO_QUARANTINE=true
QUAR_DIR="$HOME/Quarantine_OGF"
LOG_DIR="$HOME/Desktop/SafeCheck_Logs"
# ==================

TS="$(date +'%Y%m%d-%H%M%S')"
LOG_FILE="$LOG_DIR/SafeCheck_$TS.log"
BADLIST_URL="https://brokenstones.is/static/scripts/badfiles.txt"
BROKEN_SCRIPT_URL="https://brokenstones.is/static/scripts/check_badfiles.sh"
RENTRY_URLS=("https://rentry.co/ogf_malware" "https://rentry.co/ogf_malware_behavior")

mkdir -p "$LOG_DIR" "$QUAR_DIR"

# ── Language selection ──
echo "Select Language / اختر اللغة:"
echo "1) العربية"
echo "2) English"
read -rp "Enter choice (1/2): " choice
case "$choice" in
  1) LANG_CHOICE="ar" ;;
  2) LANG_CHOICE="en" ;;
  *) LANG_CHOICE="en" ;;
esac

# ── i18n helper ──
t() {
  local k="$1"
  case "$LANG_CHOICE" in
    ar)
      case "$k" in
        head) echo "🔍 فحص macOS ضد OGF / Poseidon" ;;
        credits) echo "الحقوق: Khalid | Routers.world | Tw: @REMiX_KSA" ;;
        log_at) echo "ملف السجل:" ;;
        quar_at) echo "مجلد الحجر:" ;;
        gk_head) echo "[1] حالة Gatekeeper" ;;
        gk_on) echo "✅ Gatekeeper مفعل" ;;
        gk_off) echo "⚠️ Gatekeeper معطل" ;;
        local_head) echo "[2] البصمات المحلية" ;;
        tmp_check) echo "• /tmp: البحث عن run.sh أو مجلدات TNT" ;;
        clean) echo "  ✅ نظيف" ;;
        spot_check) echo "• Spotlight: البحث عن ملفات .dat.nosync*" ;;
        appsup_check) echo "• Application Support: البحث عن .dat.nosync*" ;;
        persist_check) echo "• فحص LaunchAgents/Daemons (استثناء Google/Adobe/VPN)" ;;
        file) echo "  • ملف:" ;;
        size) echo "    - الحجم (بايت):" ;;
        kind) echo "    - النوع:" ;;
        md5_is) echo "    - md5:" ;;
        q_move) echo "🚧 نقل إلى الحجر:" ;;
        bsl_head) echo "[3] قائمة BrokenStones للـ MD5" ;;
        bsl_ok) echo "✅ تم تنزيل badfiles.txt" ;;
        bsl_fail) echo "⚠️ فشل تنزيل badfiles.txt" ;;
        scan_dir) echo "• فحص ملفات DMG (يشمل المجلدات الفرعية) داخل:" ;;
        no_dmgs) echo "  (لا توجد DMGs هنا)" ;;
        md5_hit) echo "  ❌ موجودة في badfiles.txt — ملف مُصاب" ;;
        md5_miss) echo "  ✅ غير موجودة في badfiles.txt" ;;
        ogf_dirs_head) echo "[3b] البحث عن ملفات OGF داخل المجلدات (Downloads/Desktop)" ;;
        ogf_found) echo "    ⚠️ تم العثور على OGF:" ;;
        ogf_bad) echo "    ❌ OGF مريب (Mach-O) — لا تُشغّله" ;;
        ogf_okish) echo "    ℹ️ يبدو سكربت — راجعه نصيًا قبل التشغيل" ;;
        vols) echo "• فحص المجلدات المركّبة (/Volumes) للبحث عن OGF" ;;
        vol) echo "  - مجلد مركّب:" ;;
        ogf_none) echo "    (لا يوجد OGF هنا)" ;;
        bs_run_head) echo "[4] تشغيل سكربت BrokenStones (داخل Downloads)" ;;
        bs_exec) echo "• تشغيل السكربت:" ;;
        bs_skip) echo "تم التخطي عبر الإعدادات." ;;
        rentry_head) echo "[5] التحقق من IPs (rentry)" ;;
        getting) echo "• جلب:" ;;
        collected) echo "• عدد العناوين:" ;;
        lsof_check) echo "• مقارنة الاتصالات الحالية..." ;;
        ip_match) echo "❌ توجد اتصالات تطابق قائمة rentry:" ;;
        ip_nomatch) echo "✅ لا توجد اتصالات تطابق" ;;
        ip_fail) echo "⚠️ تعذر جلب IPs من rentry" ;;
        finish) echo "✅ الفحص اكتمل" ;;
        report) echo "التقرير حُفظ في:" ;;
        quarantine_label) echo "مجلد الحجر:" ;;
      esac ;;
    *)
      case "$k" in
        head) echo "🔍 macOS OGF / Poseidon Comprehensive Scan" ;;
        credits) echo "Credits: Khalid | Routers.world | Tw: @REMiX_KSA" ;;
        log_at) echo "Log file:" ;;
        quar_at) echo "Quarantine dir:" ;;
        gk_head) echo "[1] Gatekeeper status" ;;
        gk_on) echo "✅ Gatekeeper enabled" ;;
        gk_off) echo "⚠️ Gatekeeper disabled" ;;
        local_head) echo "[2] Local artifacts" ;;
        tmp_check) echo "• /tmp: look for run.sh or TNT folders" ;;
        clean) echo "  ✅ Clean" ;;
        spot_check) echo "• Spotlight: look for .dat.nosync* files" ;;
        appsup_check) echo "• Application Support: look for .dat.nosync*" ;;
        persist_check) echo "• Persistence check (LaunchAgents/Daemons)" ;;
        file) echo "  • File:" ;;
        size) echo "    - size (bytes):" ;;
        kind) echo "    - file type:" ;;
        md5_is) echo "    - md5:" ;;
        q_move) echo "🚧 Quarantining:" ;;
        bsl_head) echo "[3] BrokenStones bad MD5 list" ;;
        bsl_ok) echo "✅ badfiles.txt downloaded" ;;
        bsl_fail) echo "⚠️ failed to download badfiles.txt" ;;
        scan_dir) echo "• Scanning DMGs (recursive) in:" ;;
        no_dmgs) echo "  (no DMGs here)" ;;
        md5_hit) echo "  ❌ MATCH in badfiles.txt — INFECTED" ;;
        md5_miss) echo "  ✅ Not in badfiles.txt" ;;
        ogf_dirs_head) echo "[3b] Searching for OGF files inside folders (Downloads/Desktop)" ;;
        ogf_found) echo "    ⚠️ Found OGF:" ;;
        ogf_bad) echo "    ❌ Suspicious OGF (Mach-O) — DO NOT RUN" ;;
        ogf_okish) echo "    ℹ️ Looks like a script — review before running" ;;
        vols) echo "• Checking mounted volumes (/Volumes) for OGF" ;;
        vol) echo "  - Volume:" ;;
        ogf_none) echo "    (no OGF here)" ;;
        bs_run_head) echo "[4] Running BrokenStones helper (in Downloads)" ;;
        bs_exec) echo "• Executing script:" ;;
        bs_skip) echo "Skipped by config." ;;
        rentry_head) echo "[5] Rentry IPs check" ;;
        getting) echo "• Fetching:" ;;
        collected) echo "• Collected IP count:" ;;
        lsof_check) echo "• Checking current connections..." ;;
        ip_match) echo "❌ Current connections match rentry IPs:" ;;
        ip_nomatch) echo "✅ No active connections matching" ;;
        ip_fail) echo "⚠️ Could not fetch IPs from rentry" ;;
        finish) echo "✅ Scan Finished" ;;
        report) echo "Report saved to:" ;;
        quarantine_label) echo "Quarantine:" ;;
      esac ;;
  esac
}

log() { echo -e "$*" | tee -a "$LOG_FILE"; }
headline() { echo "==============================" | tee -a "$LOG_FILE"; echo " $*" | tee -a "$LOG_FILE"; echo "==============================" | tee -a "$LOG_FILE"; }

move_to_quarantine() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  local base="$(basename "$path")"
  local dest="$QUAR_DIR/${TS}_$base"
  log "$(t q_move) $path -> $dest"
  mv -f "$path" "$dest" 2>>"$LOG_FILE" || { cp -a "$path" "$dest" 2>>"$LOG_FILE"; rm -rf "$path"; }
}

assess_file() {
  local f="$1"
  local size="$(stat -f %z "$f" 2>/dev/null || stat -c %s "$f" 2>/dev/null || echo 0)"
  local info="$(file "$f" 2>/dev/null || echo "unknown")"
  local md5v="$(md5 "$f" 2>/dev/null | awk '{print $4}')"
  [ -z "$md5v" ] && md5v="$(md5sum "$f" 2>/dev/null | awk '{print $1}')"
  log "$(t file) $f"
  log "  $(t size) $size"
  log "  $(t kind) $info"
  log "  $(t md5_is) ${md5v:-N/A}"
}

# ==== START REPORT ====
headline "$(t head)"
log "$(t credits)"
log "$(t log_at) $LOG_FILE"
log "$(t quar_at) $QUAR_DIR"
log ""

# [1] Gatekeeper
headline "$(t gk_head)"
if spctl --status 2>/dev/null | tee -a "$LOG_FILE" | grep -q "enabled"; then
  log "$(t gk_on)"
else
  log "$(t gk_off)"
fi

# [2] Local artifacts
headline "$(t local_head)"
log "\n$(t tmp_check)"
TMP_HIT=false
if ls /tmp 1>/dev/null 2>&1; then
  if ls /tmp 2>/dev/null | grep -qi "^run\.sh$"; then TMP_HIT=true; assess_file "/tmp/run.sh"; $AUTO_QUARANTINE && move_to_quarantine "/tmp/run.sh"; fi
  if ls /tmp 2>/dev/null | grep -qi "^tnt"; then
    TMP_HIT=true
    for f in /tmp/tnt*; do assess_file "$f"; $AUTO_QUARANTINE && move_to_quarantine "$f"; done
  fi
fi
$TMP_HIT || log "$(t clean)"

log "\n$(t spot_check)"
SPOT_FILES=$(find "$HOME/Library/Application Support/com.apple.spotlight" -type f -name ".dat.nosync*" 2>/dev/null || true)
if [ -n "$SPOT_FILES" ]; then
  while IFS= read -r f; do assess_file "$f"; $AUTO_QUARANTINE && move_to_quarantine "$f"; done <<< "$SPOT_FILES"
else log "$(t clean)"; fi

log "\n$(t appsup_check)"
APP_FILES=$(find "$HOME/Library/Application Support" -type f -name ".dat.nosync*" 2>/dev/null || true)
if [ -n "$APP_FILES" ]; then
  while IFS= read -r f; do assess_file "$f"; $AUTO_QUARANTINE && move_to_quarantine "$f"; done <<< "$APP_FILES"
else log "$(t clean)"; fi

log "\n$(t persist_check)"
for PATHX in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  log "  - $PATHX"
  if [ -d "$PATHX" ]; then
    ls -al "$PATHX" 2>/dev/null | grep -iv "google\|adobe\|keystone\|privax" | tee -a "$LOG_FILE" || true
  else log "    (missing)"; fi
done

# [3] BrokenStones MD5 (DMGs)
headline "$(t bsl_head)"
BADLIST="/tmp/badfiles.txt"
if curl -fsSL "$BADLIST_URL" -o "$BADLIST"; then log "$(t bsl_ok)"; else log "$(t bsl_fail)"; fi

check_dmgs_in_dir_recursive() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  log "\n$(t scan_dir) $dir"
  local any=false
  while IFS= read -r -d '' dmg; do
    any=true
    local md5val="$(md5 "$dmg" 2>/dev/null | awk '{print $4}')"
    [ -z "$md5val" ] && md5val="$(md5sum "$dmg" 2>/dev/null | awk '{print $1}')"
    log "  - $dmg"
    log "  $(t md5_is) $md5val"
    if [ -s "$BADLIST" ] && grep -qi "^$md5val$" "$BADLIST"; then
      log "  $(t md5_hit)"
      $AUTO_QUARANTINE && move_to_quarantine "$dmg"
    else
      log "  $(t md5_miss)"
    fi
  done < <(find "$dir" -type f \( -iname "*.dmg" -o -iname "*.DMG" \) -print0 2>/dev/null)
  $any || log "  $(t no_dmgs)"
}

for d in "${SCAN_DIRS[@]}"; do
  check_dmgs_in_dir_recursive "$d"
done

# [3b] Search for standalone "Open Gatekeeper friendly" files inside SCAN_DIRS
headline "$(t ogf_dirs_head)"
for d in "${SCAN_DIRS[@]}"; do
  while IFS= read -r -d '' f; do
    log "$(t ogf_found)"
    assess_file "$f"
    # If Mach-O -> suspicious
    if file "$f" 2>/dev/null | grep -q "Mach-O"; then
      log "$(t ogf_bad)"
      $AUTO_QUARANTINE && move_to_quarantine "$f"
    else
      log "$(t ogf_okish)"
    fi
  done < <(find "$d" -type f \( -iname "Open Gatekeeper friendly" -o -iname "Open Gatekeeper Friendly" \) -print0 2>/dev/null)
done

# Mounted volumes (OGF check)
headline "$(t vols)"
if $CHECK_MOUNTED_VOLUMES && [ -d "/Volumes" ]; then
  for vol in /Volumes/*; do
    [ -d "$vol" ] || continue
    log "$(t vol) $vol"
    OGF=$(find "$vol" -maxdepth 2 -type f \( -iname "Open Gatekeeper friendly" -o -iname "Open Gatekeeper Friendly" \) 2>/dev/null || true)
    if [ -n "$OGF" ]; then
      while IFS= read -r f; do
        log "    $(t ogf_found)"; assess_file "$f"
        if file "$f" 2>/dev/null | grep -q "Mach-O"; then
          log "    $(t ogf_bad)"; $AUTO_QUARANTINE && move_to_quarantine "$f"
        else
          log "    $(t ogf_okish)"
        fi
      done <<< "$OGF"
    else log "    $(t ogf_none)"; fi
  done
fi

# [4] BrokenStones helper
headline "$(t bs_run_head)"
if $RUN_BROKENSTONES_SCRIPT && [ -d "$HOME/Downloads" ]; then
  ( cd "$HOME/Downloads"
    log "$(t bs_exec) $BROKEN_SCRIPT_URL"
    curl -fsSL "$BROKEN_SCRIPT_URL" | bash 2>&1 | tee -a "$LOG_FILE" || true )
else log "$(t bs_skip)"; fi

# [5] Rentry IPs
headline "$(t rentry_head)"
if $CHECK_RENTRY_IPS; then
  TMP_IPS="/tmp/ogf_ips_$TS.txt"; : > "$TMP_IPS"
  for u in "${RENTRY_URLS[@]}"; do log "$(t getting) $u"; curl -fsSL "$u" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -Vu >> "$TMP_IPS" || true; done
  if [ -s "$TMP_IPS" ]; then
    log "$(t collected) $(wc -l < "$TMP_IPS")"
    log "$(t lsof_check)"
    CUR=$(lsof -nPi 2>/dev/null | awk '{print $9}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -Vu || true)
    MATCHES=$(comm -12 <(echo "$CUR") <(sort -Vu "$TMP_IPS") || true)
    if [ -n "$MATCHES" ]; then log "$(t ip_match)"; echo "$MATCHES" | tee -a "$LOG_FILE"; else log "$(t ip_nomatch)"; fi
  else log "$(t ip_fail)"; fi
else log "$(t bs_skip)"; fi

headline "$(t finish)"
log "$(t report) $LOG_FILE"
log "$(t quarantine_label) $QUAR_DIR"
