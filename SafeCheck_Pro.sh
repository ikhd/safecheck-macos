#!/bin/bash
set -euo pipefail

# ───────────────────────────────────────────────
# SafeCheck_Pro v1.1 — OGF/Poseidon macOS quick scan (DMG/OGF + .app bundles)
# Credits: Khalid | Routers.world | Tw: @REMiX_KSA
# ───────────────────────────────────────────────

# ===== Config =====
SCAN_DIRS=("$HOME/Downloads" "$HOME/Desktop")  # recursive scan
CHECK_MOUNTED_VOLUMES=true
RUN_BROKENSTONES_SCRIPT=true
CHECK_RENTRY_IPS=true
AUTO_QUARANTINE=true
CHECK_APP_BUNDLES=true
QUAR_DIR="$HOME/Quarantine_OGF"
LOG_DIR="$HOME/Desktop/SafeCheck_Logs"
SKIP_INTERNAL_VOLUMES=true
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

# ── Ask for verbosity ──
if [ "${LANG_CHOICE}" = "ar" ]; then
  echo "هل تريد تفعيل (التفاصيل الكاملة) أثناء التشغيل؟"
  echo "1) نعم (مفصل)"
  echo "2) لا (ملخص فقط على الشاشة، وكل التفاصيل في ملف السجل)"
  read -rp "اختر (1/2): " vchoice
else
  echo "Enable detailed output during run?"
  echo "1) Yes (verbose)"
  echo "2) No (show summary only on screen; full details in log)"
  read -rp "Choose (1/2): " vchoice
fi
case "$vchoice" in
  1) VERBOSE=1 ;;
  2) VERBOSE=0 ;;
  *) VERBOSE=1 ;;
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
        ogf_none) echo "    (لا يوجد عناصر هنا)" ;;
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
        app_header) echo "[3c] فحص حزم التطبيقات (.app)" ;;
        app_ok) echo "سليم" ;;
        app_warn) echo "تحذير" ;;
        app_quar) echo "حُجِر" ;;
        stats_head) echo "📊 ملخص النتائج" ;;
        stats_ok) echo "• سليم:" ;;
        stats_warn) echo "• تحذير:" ;;
        stats_quar) echo "• محجور:" ;;
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
        ogf_none) echo "    (no items here)" ;;
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
        app_header) echo "[3c] Scanning .app bundles" ;;
        app_ok) echo "OK" ;;
        app_warn) echo "Warning" ;;
        app_quar) echo "Quarantined" ;;
        stats_head) echo "📊 Results summary" ;;
        stats_ok) echo "• OK:" ;;
        stats_warn) echo "• Warning:" ;;
        stats_quar) echo "• Quarantined:" ;;
      esac ;;
  esac
}

# ── Logging helpers ──
log() { echo -e "$*" | tee -a "$LOG_FILE"; }
vlog() {
  if [ "${VERBOSE:-1}" -eq 1 ]; then
    echo -e "$*" | tee -a "$LOG_FILE"
  else
    echo -e "$*" >> "$LOG_FILE"
  fi
}
headline() { echo "==============================" | tee -a "$LOG_FILE"; echo " $*" | tee -a "$LOG_FILE"; echo "==============================" | tee -a "$LOG_FILE"; }

move_to_quarantine() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  local base; base="$(basename "$path")"
  local dest="$QUAR_DIR/${TS}_$base"
  log "$(t q_move) $path -> $dest"
  mv -f "$path" "$dest" 2>>"$LOG_FILE" || { cp -a "$path" "$dest" 2>>"$LOG_FILE"; rm -rf "$path"; }
}

assess_file() {
  local f="$1"
  local size="$(stat -f %z "$f" 2>/dev/null || stat -c %s "$f" 2>/dev/null || echo 0)"
  local info="$(file "$f" 2>/dev/null || echo "unknown")"
  local md5v="$(md5 -q "$f" 2>/dev/null || true)"
  [ -z "$md5v" ] && md5v="$(md5sum "$f" 2>/dev/null | awk '{print $1}' || true)"
  vlog "$(t file) $f"
  vlog "  $(t size) $size"
  vlog "  $(t kind) $info"
  vlog "  $(t md5_is) ${md5v:-N/A}"
}

# ── counters for summary ──
APP_OK=0
APP_WARN=0
APP_QUAR=0

# ── .app bundle helpers ────────────────────────────────────────────────
get_app_main_exec() {
  local app="$1"
  local plist="$app/Contents/Info.plist"
  local exe=""
  if [ -f "$plist" ]; then
    if command -v /usr/libexec/PlistBuddy >/dev/null 2>&1; then
      exe=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$plist" 2>/dev/null || echo "")
    fi
    if [ -z "$exe" ] && [ -d "$app/Contents/MacOS" ]; then
      exe="$(find "$app/Contents/MacOS" -maxdepth 1 -type f -perm -111 -print -quit 2>/dev/null || true)"
    else
      [ -n "$exe" ] && exe="$app/Contents/MacOS/$exe"
    fi
  fi
  [ -n "$exe" ] && [ -f "$exe" ] && echo "$exe" || echo ""
}

assess_app_bundle() {
  local app="$1"
  local name="$(basename "$app")"
  local summary_reasons=()
  local status="OK"
  local quarantined="no"

  vlog "$(t file) $app"

  # Bundle size & quarantine xattr
  local size_kb="$(du -sk "$app" 2>/dev/null | awk '{print $1 " KB"}')"
  vlog "  • bundle size (KB): ${size_kb:-N/A}"
  local qtag="$(xattr -p com.apple.quarantine "$app" 2>/dev/null || echo "none")"
  vlog "  • quarantine xattr: $qtag"

  # Main executable
  local mainexe; mainexe="$(get_app_main_exec "$app")"
  if [ -z "$mainexe" ]; then
    vlog "  • main exec: not found"
    status="Warning"; summary_reasons+=("main-exec-missing")
  else
    local finfo="$(file "$mainexe" 2>/dev/null || echo "unknown")"
    local md5v="$(md5 -q "$mainexe" 2>/dev/null || true)"
    [ -z "$md5v" ] && md5v="$(md5sum "$mainexe" 2>/dev/null | awk '{print $1}' || true)"
    vlog "  • main exec: $mainexe"
    vlog "    $(t kind) $finfo"
    vlog "    $(t md5_is) ${md5v:-N/A}"

    # Match MD5 of main exec against badlist if available
    if [ -s "${BADLIST:-}" ] && [ -n "$md5v" ]; then
      if grep -qi "^$md5v$" "$BADLIST"; then
        vlog "    ❌ MATCH in badfiles.txt — INFECTED (main exec)"
        summary_reasons+=("badlist-hit")
        status="Warning"
        if $AUTO_QUARANTINE; then
          move_to_quarantine "$app"
          quarantined="yes"
          status="Quarantined"
        fi
      fi
    fi

    # Signature / Notarization if Mach-O
    if file "$mainexe" 2>/dev/null | grep -q "Mach-O"; then
      local cs_out; cs_out="$(codesign -dv --verbose=4 "$app" 2>&1 || true)"
      vlog "  • codesign:"
      printf "%s\n" "$cs_out" | sed 's/^/      /' | tee -a "$LOG_FILE" >/dev/null

      # مختصر codesign
      local teamid="$(printf '%s\n' "$cs_out" | awk -F'= *' '/TeamIdentifier/{print $2; exit}')"
      local auth="$(printf '%s\n' "$cs_out" | awk -F'= *' '/Authority=/{print $2}' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | paste -sd' > ' -)"
      [ -n "$teamid" ] && vlog "    • TeamID: $teamid"
      [ -n "$auth" ] && vlog "    • Authority: $auth"

      local sp_out; sp_out="$(spctl -a -vv "$app" 2>&1 || true)"
      vlog "  • spctl:"
      printf "%s\n" "$sp_out" | sed 's/^/      /' | tee -a "$LOG_FILE" >/dev/null 2>&1 || true

      # مختصر spctl
      local sp_status="unknown"
      printf '%s\n' "$sp_out" | grep -qi 'accepted' && sp_status="accepted"
      printf '%s\n' "$sp_out" | grep -qi 'rejected' && sp_status="rejected"
      [ "$sp_status" != "unknown" ] && vlog "    • Gatekeeper: $sp_status"

      local sp_origin="$(printf '%s\n' "$sp_out" | awk -F'= *' '/origin=/{print $2; exit}')"
      [ -n "$sp_origin" ] && vlog "    • Origin: $sp_origin"

      # قرارات
      if echo "$cs_out" | grep -qi "code object is not signed"; then
        summary_reasons+=("unsigned")
        status="Warning"
        if $AUTO_QUARANTINE; then
          move_to_quarantine "$app"
          quarantined="yes"
          status="Quarantined"
        fi
      elif [ "$sp_status" = "rejected" ]; then
        summary_reasons+=("gatekeeper-rejected")
        status="Warning"
        if $AUTO_QUARANTINE; then
          move_to_quarantine "$app"
          quarantined="yes"
          status="Quarantined"
        fi
      fi

      # إذا everything OK ومعروف TeamID
      if [ "$status" = "OK" ] && [ -n "${teamid:-}" ]; then
        summary_reasons+=("TeamID=$teamid")
      fi

    else
      # Not Mach-O main exec (rare for normal apps)
      summary_reasons+=("non-MachO-main")
      status="Warning"
    fi
  fi

  # تحديث العدادات + طباعة ملخص سطر واحد للمستخدم
  local tag_ok="$(t app_ok)"
  local tag_warn="$(t app_warn)"
  local tag_quar="$(t app_quar)"
  local reasons_joined; reasons_joined="$(IFS=';'; echo "${summary_reasons[*]-}")"

  case "$status" in
    Quarantined) APP_QUAR=$((APP_QUAR+1)); log "  • $name — [$tag_quar] ${reasons_joined:-}";;
    Warning)     APP_WARN=$((APP_WARN+1)); log "  • $name — [$tag_warn] ${reasons_joined:-}";;
    *)           APP_OK=$((APP_OK+1));     log "  • $name — [$tag_ok] ${reasons_joined:-}";;
  esac
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
vlog "\n$(t tmp_check)"
TMP_HIT=false
if ls /tmp 1>/dev/null 2>&1; then
  if ls /tmp 2>/dev/null | grep -qi "^run\.sh$"; then TMP_HIT=true; assess_file "/tmp/run.sh"; $AUTO_QUARANTINE && move_to_quarantine "/tmp/run.sh"; fi
  if ls /tmp 2>/dev/null | grep -qi "^tnt"; then
    TMP_HIT=true
    for f in /tmp/tnt*; do assess_file "$f"; $AUTO_QUARANTINE && move_to_quarantine "$f"; done
  fi
fi
$TMP_HIT || vlog "$(t clean)"

vlog "\n$(t spot_check)"
SPOT_FILES=$(find "$HOME/Library/Application Support/com.apple.spotlight" -type f -name ".dat.nosync*" 2>/dev/null || true)
if [ -n "$SPOT_FILES" ]; then
  while IFS= read -r f; do assess_file "$f"; $AUTO_QUARANTINE && move_to_quarantine "$f"; done <<< "$SPOT_FILES"
else vlog "$(t clean)"; fi

vlog "\n$(t appsup_check)"
APP_FILES=$(find "$HOME/Library/Application Support" -type f -name ".dat.nosync*" 2>/dev/null || true)
if [ -n "$APP_FILES" ]; then
  while IFS= read -r f; do assess_file "$f"; $AUTO_QUARANTINE && move_to_quarantine "$f"; done <<< "$APP_FILES"
else vlog "$(t clean)"; fi

vlog "\n$(t persist_check)"
for PATHX in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  vlog "  - $PATHX"
  if [ -d "$PATHX" ]; then
    ls -al "$PATHX" 2>/dev/null | grep -iv "google\|adobe\|keystone\|privax" | tee -a "$LOG_FILE" >/dev/null || true
  else vlog "    (missing)"; fi
done

# [3] BrokenStones MD5 (DMGs)
headline "$(t bsl_head)"
BADLIST="/tmp/badfiles.txt"
if curl -fsSL "$BADLIST_URL" -o "$BADLIST"; then log "$(t bsl_ok)"; else log "$(t bsl_fail)"; fi

check_dmgs_in_dir_recursive() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  vlog "\n$(t scan_dir) $dir"
  local any=false
  while IFS= read -r -d '' dmg; do
    any=true
    local md5val="$(md5 -q "$dmg" 2>/dev/null || true)"
    [ -z "$md5val" ] && md5val="$(md5sum "$dmg" 2>/dev/null | awk '{print $1}' || true)"
    vlog "  - $dmg"
    vlog "  $(t md5_is) $md5val"
    if [ -s "$BADLIST" ] && grep -qi "^$md5val$" "$BADLIST"; then
      vlog "  $(t md5_hit)"
      $AUTO_QUARANTINE && move_to_quarantine "$dmg"
    else
      vlog "  $(t md5_miss)"
    fi
  done < <(find "$dir" -type f \( -iname "*.dmg" -o -iname "*.DMG" \) -print0 2>/dev/null)
  $any || vlog "  $(t no_dmgs)"
}

for d in "${SCAN_DIRS[@]}"; do
  check_dmgs_in_dir_recursive "$d"
done

# [3b] Search for standalone "Open Gatekeeper friendly" files inside SCAN_DIRS
headline "$(t ogf_dirs_head)"
for d in "${SCAN_DIRS[@]}"; do
  while IFS= read -r -d '' f; do
    vlog "$(t ogf_found)"
    assess_file "$f"
    if file "$f" 2>/dev/null | grep -q "Mach-O"; then
      vlog "$(t ogf_bad)"
      $AUTO_QUARANTINE && move_to_quarantine "$f"
    else
      vlog "$(t ogf_okish)"
    fi
  done < <(find "$d" -type f \( -iname "Open Gatekeeper friendly" -o -iname "Open Gatekeeper Friendly" \) -print0 2>/dev/null)
done

# [3c] Scan for .app bundles (Application / Universal)
headline "$(t app_header)"
if ${CHECK_APP_BUNDLES:-false}; then
  for d in "${SCAN_DIRS[@]}"; do
    [ -d "$d" ] || continue
    log "• Directory: $d"
    found=false
    while IFS= read -r -d '' app; do
      found=true
      assess_app_bundle "$app"
    done < <(find "$d" -type d -name "*.app" -prune -print0 2>/dev/null)
    $found || log "  $(t clean)"
  done
else
  log "$(t bs_skip)"
fi

# Mounted volumes (OGF/.app check)
headline "$(t vols)"
if $CHECK_MOUNTED_VOLUMES && [ -d "/Volumes" ]; then
  for vol in /Volumes/*; do
    [ -d "$vol" ] || continue

    # تخطّي وحدات النظام الداخلية (اختياري)
    if ${SKIP_INTERNAL_VOLUMES:-true}; then
      root_dev="$(df / | tail -1 | awk '{print $1}')"
      vol_dev="$(df "$vol" | tail -1 | awk '{print $1}')"
      if [ "$vol_dev" = "$root_dev" ]; then
        continue
      fi
      case "$(basename "$vol")" in
        "Macintosh HD"|"Macintosh HD - Data") continue ;;
      esac
    fi

    log "$(t vol) $vol"

    # OGF files on mounted volumes
    OGF=$(find "$vol" -maxdepth 2 -type f \( -iname "Open Gatekeeper friendly" -o -iname "Open Gatekeeper Friendly" \) 2>/dev/null || true)
    if [ -n "$OGF" ]; then
      while IFS= read -r f; do
        vlog "    $(t ogf_found)"; assess_file "$f"
        if file "$f" 2>/dev/null | grep -q "Mach-O"; then
          vlog "    $(t ogf_bad)"; $AUTO_QUARANTINE && move_to_quarantine "$f"
        else
          vlog "    $(t ogf_okish)"
        fi
      done <<< "$OGF"
    else vlog "    $(t ogf_none)"; fi

    # .app bundles on mounted volumes
    if ${CHECK_APP_BUNDLES:-false}; then
      vlog "  - Scanning .app bundles in: $vol"
      vfound=false
      while IFS= read -r -d '' app; do
        vfound=true
        assess_app_bundle "$app"
      done < <(find "$vol" -maxdepth 3 -type d -name "*.app" -prune -print0 2>/dev/null)
      $vfound || vlog "    $(t ogf_none)"
    fi
  done
fi

# [4] BrokenStones helper
headline "$(t bs_run_head)"
if $RUN_BROKENSTONES_SCRIPT && [ -d "$HOME/Downloads" ]; then
  (
    cd "$HOME/Downloads"
    log "$(t bs_exec) $BROKEN_SCRIPT_URL"
    curl -fsSL "$BROKEN_SCRIPT_URL" | bash 2>&1 | tee -a "$LOG_FILE" || true
  )
else
  log "$(t bs_skip)"
fi

# [5] Rentry IPs
headline "$(t rentry_head)"
if $CHECK_RENTRY_IPS; then
  TMP_IPS="/tmp/ogf_ips_$TS.txt"; : > "$TMP_IPS"
  for u in "${RENTRY_URLS[@]}"; do
    log "$(t getting) $u"
    curl -fsSL "$u" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -Vu >> "$TMP_IPS" || true
  done
  if [ -s "$TMP_IPS" ]; then
    log "$(t collected) $(wc -l < "$TMP_IPS")"
    log "$(t lsof_check)"
    CUR=$(lsof -nPi 2>/dev/null | awk '{print $9}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -Vu || true)
    MATCHES=$(comm -12 <(echo "$CUR") <(sort -Vu "$TMP_IPS") || true)
    if [ -n "$MATCHES" ]; then
      log "$(t ip_match)"
      echo "$MATCHES" | tee -a "$LOG_FILE"
    else
      log "$(t ip_nomatch)"
    fi
  else
    log "$(t ip_fail)"
  fi
else
  log "$(t bs_skip)"
fi

# 📊 Summary
headline "$(t stats_head)"
log "$(t stats_ok)   $APP_OK"
log "$(t stats_warn) $APP_WARN"
log "$(t stats_quar) $APP_QUAR"

headline "$(t finish)"
log "$(t report) $LOG_FILE"
log "$(t quarantine_label) $QUAR_DIR"
