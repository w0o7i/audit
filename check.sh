#!/usr/bin/env bash

# Цвета для удобства
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[1;34m'; N='\033[0m'
SCORE=0

print_header() { printf "\n${B}▶ %s${N}\n" "$1"; }

# 1. СИСТЕМНАЯ ИНФОРМАЦИЯ
print_sys_info() {
    print_header "ИНФОРМАЦИЯ О СИСТЕМЕ"
    printf "Ядро: %s\n" "$(uname -r)"
    printf "Uptime: %s\n" "$(uptime -p)"
    printf "Текущий пользователь: %s\n" "$(whoami)"
    printf "ptrace_scope (YAMA): %s\n" "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 'N/A')"
}

# 2. АНАЛИЗ ПАМЯТИ
print_maps() {
    print_header "АНАЛИЗ ПАМЯТИ ПРОЦЕССА (PID: $PID)"
    local rwx=$(grep 'rwx' "/proc/$PID/maps" 2>/dev/null)
    if [[ -n "$rwx" ]]; then
        printf "${R}⚠ ОБНАРУЖЕНЫ RWX-СЕГМЕНТЫ!${N}\n"; SCORE=$((SCORE + 40))
    else
        printf "${G}✓ Сегменты памяти (RWX) не обнаружены${N}\n"
    fi
}

# 3. ПОИСК СЛЕДОВ (FORENSICS)
print_forensics() {
    print_header "ПОИСК СЛЕДОВ (FORENSICS)"
    if [[ -s "/etc/ld.so.preload" ]]; then
        printf "${R}⚠ /etc/ld.so.preload ЗАПОЛНЕН!${N}\n"; SCORE=$((SCORE + 50))
    else
        printf "${G}✓ /etc/ld.so.preload пуст${N}\n"
    fi
    local deleted=$(readlink /proc/$PID/exe 2>/dev/null | grep "(deleted)")
    if [[ -n "$deleted" ]]; then
        printf "${R}⚠ ПРОЦЕСС-ПРИЗРАК (EXE УДАЛЕН)!${N}\n"; SCORE=$((SCORE + 40))
    else
        printf "${G}✓ Исполняемый файл доступен${N}\n"
    fi
}

# 4. СКРЫТЫЕ ПРОЦЕССЫ
find_hidden() {
    print_header "ПОИСК СКРЫТЫХ ПРОЦЕССОВ"
    local hidden_found=false
    for p in /proc/[0-9]*; do
        local pid="${p##*/}"
        if ! ps -p "$pid" >/dev/null 2>&1 && [ -f "$p/cmdline" ] && [ -s "$p/cmdline" ]; then
            printf "${R}⚠ СКРЫТЫЙ ПРОЦЕСС ОБНАРУЖЕН: PID %s${N}\n" "$pid"
            hidden_found=true; SCORE=$((SCORE + 30))
        fi
    done
    [[ "$hidden_found" == false ]] && printf "${G}✓ Скрытых процессов не обнаружено${N}\n"
}

# 5. ГЛУБОКИЙ АНАЛИЗ (PRO)
check_deep_analysis() {
    print_header "ГЛУБОКИЙ АНАЛИЗ ПРОЦЕССА"
    local tracer_pid=$(grep "TracerPid" "/proc/$PID/status" | awk '{print $2}')
    if [[ "$tracer_pid" -ne 0 ]]; then
        printf "${R}⚠ ВНИМАНИЕ: К процессу подключен PID: %s!${N}\n" "$tracer_pid"
        SCORE=$((SCORE + 60))
    else
        printf "${G}✓ Прямых дебаггеров/инжекторов не обнаружено${N}\n"
    fi
    local anon_mem=$(grep '\[anon\]' "/proc/$PID/maps" 2>/dev/null)
    if [[ -n "$anon_mem" ]]; then
        printf "${Y}ℹ Обнаружены анонимные сегменты памяти.${N}\n"; SCORE=$((SCORE + 15))
    else
        printf "${G}✓ Анонимных сегментов не обнаружено${N}\n"
    fi
}

# 6. ФАЙЛЫ И БИБЛИОТЕКИ
check_files_and_libs() {
    print_header "АНАЛИЗ ОТКРЫТЫХ ФАЙЛОВ И БИБЛИОТЕК"
    local suspicious_files=$(sudo ls -l /proc/$PID/fd 2>/dev/null | grep -E "/tmp|/dev/shm|\.so|\.py|\.sh")
    if [[ -n "$suspicious_files" ]]; then
        printf "${R}⚠ ВНИМАНИЕ: Подозрительные файлы в дескрипторах!${N}\n"; SCORE=$((SCORE + 25))
    else
        printf "${G}✓ Подозрительных файловых дескрипторов нет${N}\n"
    fi

    local suspicious_libs=$(grep "/" "/proc/$PID/maps" | awk '{print $6}' | grep -vE "/usr/lib|/lib|/libc|\[vdso\]|\[vvar\]|\[stack\]|\[heap\]|\[aio\]|cstrike_linux64" | sort -u)
    if [[ -n "$suspicious_libs" ]]; then
        printf "${Y}⚠ ОБНАРУЖЕНЫ БИБЛИОТЕКИ ВНЕ СИСТЕМНЫХ ПУТЕЙ:${N}\n"
        echo "$suspicious_libs"; SCORE=$((SCORE + 20))
    else
        printf "${G}✓ Все библиотеки из доверенных путей${N}\n"
    fi
}

check_network() {
    print_header "АНАЛИЗ СЕТЕВОЙ АКТИВНОСТИ"
    
    # Ищем сетевые сокеты, принадлежащие нашему PID
    # -t: TCP, -u: UDP, -p: показать процесс, -n: не разрешать имена (быстрее)
    local net_info=$(ss -tulpn | grep "pid=$PID" 2>/dev/null)
    
    if [[ -n "$net_info" ]]; then
        printf "${Y}⚠ ВНИМАНИЕ: Процесс использует сетевые порты!${N}\n"
        echo "$net_info"
        # Даем индекс угрозы, если процесс открыл порт наружу (0.0.0.0 или ::)
        if echo "$net_info" | grep -qE "0.0.0.0|:::"; then
            printf "${R}⚠ ПОРТ ОТКРЫТ НА ВХОД (Listening)!${N}\n"
            SCORE=$((SCORE + 35))
        fi
    else
        printf "${G}✓ Сетевая активность не обнаружена${N}\n"
    fi
}

# --- MAIN ---
[[ $EUID -ne 0 ]] && { echo "Нужен sudo!"; exit 1; }
PID=$(pgrep -f "cstrike_linux")
if [[ -z "$PID" ]]; then
    printf "${R}Ошибка: Целевой процесс не найден!${N}\n"; exit 1
fi

clear
print_sys_info
print_maps
print_forensics
find_hidden
check_deep_analysis
check_files_and_libs
check_network

print_header "ИТОГОВЫЙ ВЕРДИКТ"
printf "Итоговый индекс угрозы: %s\n" "$SCORE"
if [ "$SCORE" -eq 0 ]; then
    printf "${G}✅ СИСТЕМА ЧИСТА. Угроз не обнаружено.${N}\n"
elif [ "$SCORE" -lt 30 ]; then
    printf "${Y}⚠ ПОДОЗРИТЕЛЬНО. Проверьте логи.${N}\n"
else
    printf "${R}❌ ТРЕВОГА! ВЫСОКИЙ РИСК!${N}\n"
fi