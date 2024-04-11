#===========================================================
# Crepes
#===========================================================
alias grep='grep --color=auto' # grep $MUSTER auf LSD
alias grepn='grep -iRn' # Rekursive Suche mit Zeilennummerausgabe
alias fgrep='fgrep --color=auto' # Schneller als grep aber ohne Regex
alias egrep='grep -iE --color=auto' # Erweiterten Regex-Möglichkeiten
alias grepv='grep -vE "(#|^$)"' # Haut mit '#' anfangende Kommentare aus den $CONFIGS

grepalias() { alias | grep 'grep' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# Informationsbeschaffung
#===========================================================
alias os='lsb_release -a' # OS-Version
alias myshell='ps -p $$' # Aktuelle Shell
alias header='curl -I' # Headeranzeige eines $ZIEL
alias dmesg='dmesg -Tx' # Kernelmeldungen in schön
alias mem='free -m -l -t' # Ausführliche Memoryangabe
alias df='df -Th --total' # Anzeige Festplattenbelegung
alias mountt='mount | column -t' # Ausführliche Mountpoints
alias myip='curl ipinfo.io/ip' # Anzeige eigene, externe IP
alias fastping='ping -c 100 -s.2' # Ping auf Steroide $ZIEL
alias aports='netstat -tulanp' # Anzeige aller TCP/UDP-Ports
alias nlsof='lsof -n -P -i +c 15' # Übersicht Netzwerkverbindungen
alias log='lastlog | grep -vi "\*\*"' # Letzte Logins aller User
alias lports='netstat -tulanp | grep LISTEN' # Anzeige aller offenen Ports
alias dux='du -h --max-depth=1 | sort -rh' # Nach Größe sortierte Ordnerübersicht
alias dux10='du -hsx * | sort -rh | head -10' # Die 10 Größten Ordner anzeigen
alias ifconfig='ip -br -c addr show' # Kompakte Anzeige aller IP-Adressen in Farbe
alias dff='df -hlT --exclude-type=tmpfs --exclude-type=devtmpfs' # Anzeige Festplattenbelegung ohne tmpfs-Systeme

#===========================================================
# Misc
#===========================================================
alias c='clear' # Screen putzen
alias h='history' # Anzeige der Befehlshistory
alias sudo='sudo ' # Damit Aliases auch mit sudo genutzt werden können
alias cp='cp -i' # Beckenrandschwimmer-Abfrage beim kopieren ob überschrieben werden soll 
alias mv='mv -i' # Abfrage/Doppelter Boden beim verschieben ob überschrieben werden soll 
alias tmux='tmux -2' # Stabiler Terminal-Multiplexer
alias tailf='tail -f' # Fortlaufen Ausgabe einer $LOGDATEIN
alias l='ls --color=auto -CF' # Ordnerinhalte anzeigen
alias ll='ls --color=auto -l' # Ordnerinhalte als Liste anzeigen
alias lshide='ls -ld .* --color=auto' # Versteckte Daten anzeigen
alias la='ls --color=auto -A' # Ordnerinhalte inklusiver versteckter Daten anzeigen
alias lso='stat -c "%A %a %n" -L' # Übersichtliche Anzeige der Berechtigung von $DATEI
alias lll='ls --color=auto -la' # Ordnerinhalte als Liste inklusiver versteckter Daten anzeigen
alias ht='export HISTTIMEFORMAT="%F %T"' # Anzeige der Befehlshistory inkl Zeitstempel
alias hg='history | grep -i --color=auto' # Durchsuchen der Befehlshistory
alias atime="date +'%Y-%m-%d-%H-%M-%S'" # Ausführliche Datumsanzeige inkl Uhrzeit
alias bashreload='source ~/.bashrc && echo Bash reloaded' # Bash-File reloaden

#===========================================================
# Ordner
#===========================================================
eval "`dircolors`"
alias ..='cd ..'
alias ...='cd ../../../'
alias ....='cd ../../../../'
alias dir='dir --color=auto'
alias vdir='vdir --color=auto'

diralias() { alias | grep -E 'cd|dir|vdir' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# Paketmanagement
#===========================================================
alias show='apt show' # Infos zu einem $PAKET
alias remove='apt purge' # $PAKET inkl Configs droppen
alias search='apt search' # Nach einem Muster in den $PAKETEN suchen
alias install='apt install -R' # $PAKET wird ohne Rücksicht auf Verluste installiert
alias autoremove='apt autoremove' # Deinstalliert nicht mehr benutze $PAKETE
alias software='dpkg --get-selections' # Anzeige aller $PAKETE inkl Statusflag
alias fupgrade='apt install --only-upgrade' # Upgrade der vorhandenen $PAKETE
alias update='apt update && apt upgrade' # Update der Paketlisten + Pakete
alias autoclean='apt clean && apt autoclean && apt autoremove --purge' # Apt-Cleanup
alias check='ls -l /var/run/reboot-required 2>/dev/null || echo "No reboot required"' # Muss das System nach einem Update rebootet werden

aptalias() { alias | grep -E 'apt|dpkg|required' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# Programm - DNS
#===========================================================
alias dns-a='dig +noall +answer +ttlid -t A'        # Azeige $ZIEL A-Records
alias dns-mx='dig +noall +answer +ttlid -t MX'      # Azeige $ZIEL MX-Records
alias dns-ns='dig +noall +answer +ttlid -t NS'      # Azeige $ZIEL NS-Records
alias dns-any='dig +noall +answer +ttlid -t ANY'    # Azeige $ZIEL ANY-Records
alias dns-txt='dig +noall +answer +ttlid -t TXT'    # Azeige $ZIEL TXT-Records
alias dns-soa='dig +noall +answer +ttlid +nssearch' # Azeige $ZIEL SOA-Records
alias dns-rev='dig +noall +answer +ttlid -t ANY -x' # Anuzeige $ZIEL IP-Reverse-Lookup

dnsalias() { alias | grep 'dns' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# Programm - Firewall
#===========================================================
alias fwl='/sbin/iptables -L -n -v --line-numbers' # Nummerierte Anzeige der Regeln
alias fw='fwl' # Eine Alias für den oberen fwl-Aliase ;)
alias fwin='/sbin/iptables -L INPUT -n -v --line-numbers'   # Anzeige aller INPUT-Regeln
alias fwout='/sbin/iptables -L OUTPUT -n -v --line-numbers' # Anzeige aller OUTPUT-Regeln
alias fwfw='/sbin/iptables -L FORWARD -n -v --line-numbers' # Anzeige aller FORWARD-Regeln
alias fwall='iptables -vL -t filter && iptables -vL -t nat && iptables -vL -t mangle && iptables -vL -t raw && iptables -vL -t security && iptables -vL --line-numbers' # Anzeige wirklich aller Firewall-Table-Regeln

fwalias() { alias | grep 'iptables' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# Programm - Nmap
#===========================================================
alias npv='nmap -Pn --script vuln' # Schwachstellen Scan $ZIEL
alias npssl='nmap --script=ssl-cert -p 443' # SSL-Zertifikat Scan $ZIEL
alias np='nmap -p 1-65535 -T4 -r -v' # Scannt alle Ports des angegebenen $ZIEL
alias npddos='nmap -max-parallelism 600 -Pn --script http-slowloris --script-args http-slowloris.runforever=true' # DDOS-Test $ZIEL

nmapalias() { alias | grep 'nmap' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# Prozesse
#===========================================================
alias pss='ps axjfwww' # Anzeige der Prozesse als Baumliste
alias pscpu='ps auxwww | sort -nr -k 3' # Prozesse nach CPU sortieren
alias psmem='ps auxwww | sort -nr -k 4'  # Prozesse nach RAM sortieren
alias pscpu10='ps auxwww | sort -nr -k 3 | head -10'  # Die 10 CPU-hungrigsten Prozesse
alias psmem10='ps auxwww | sort -nr -k 4 | head -10' # Die 10 RAM-hungrigsten Prozesse
alias psg='ps auxwww | grep -v grep | grep -i --color=auto' # grep nach einem Prozess

psalias() { alias | grep -E '\sps.+\=' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/" | sed "s/['|\']//g" | sort; }

#===========================================================
# Security
#===========================================================
alias shred='shred -n 20 -z -u' # $DATEI hardcore shreddern
alias crontab='crontab -i' # Verhindert das löschen der crontab
alias sha='sha512sum' # Stabilere SHA-Checksumme benutzen
alias pass='openssl rand -base64' # Stabile Passwortgenerieren. $ANZAHL angeben
alias rm='rm -I --preserve-root' # Abfrage beim löschen von $DATEN ohne Slash zu entfernen
alias sshkeyinfo='for keyfile in ~/.ssh/id_*; do ssh-keygen -l -f "${keyfile}"; done | uniq' # Infos zu allen SSH-Keys im Home-Verzeichnis
alias sshkey='ssh-keygen -o -a 100 -t ed25519 -f ~/.ssh/id_$(whoami)@$(hostname -f)_ed25519 -C "$(whoami)@$(hostname -f)-$(date -I)"' # Sicherer SSH-Key mit Elliptische Kurven
alias sshkey-rsa='ssh-keygen -o -a 100 -t rsa -b 4096 -f ~/.ssh/id_$(whoami)@$(hostname -f)_rsa -C "$(whoami)@$(hostname -f)-$(date -I)"' # Sicherer 4096 Bits RSA SSH-Key ohne Elliptische Kurven

#===========================================================
# Systemctl
#===========================================================
alias start='systemctl start' # $DIENST starten
alias stop='systemctl stop' # $DIENST stoppen
alias reload='systemctl reload' # $DIENST reloaden
alias restart='systemctl restart' # $DIENST restarten
alias enable='systemctl enable' # $DIENST aktivieren
alias disable='systemctl disable' # $DIENST deaktivieren
alias status='systemctl status' # $DIENST Statusabfrage
alias running='systemctl list-units  --type=service  --state=running'
alias systemdconf='systemctl cat' # $DIENST-Konfiguration anzeigen
alias systemddep='systemctl list-dependencies' # $DIENST-Abhängikeiten anzeigen
alias stats='systemctl list-units --type=service' # Infos zu allen von Systemd kontrollierten Diensten

sysalias() { alias | grep 'systemctl' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# Programm - Docker
#===========================================================
alias dops="docker ps"
alias dopa="docker ps -a"
alias doi="docker images"
alias dos="docker search"
alias dokd="docker run -d -P"
alias doex="docker exec -i -t"
alias doki="docker run -i -t -P"
alias dtail='docker logs -tf --tail="50" "$@"'
alias doip="docker inspect --format '{{ .NetworkSettings.IPAddress }}'"
alias dormf='docker stop $(docker ps -a -q) && docker rm $(docker ps -a -q)'

dostop() { docker stop $(docker ps -a -q); }
dorm() { docker rm $(docker ps -a -q); }
dori() { docker rmi $(docker images -q); }
dorin() { docker rmi -f $(docker images --filter "dangling=true" -q); }

doalias() { alias | grep 'docker' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

#===========================================================
# X-Custom
#===========================================================
alias apache-t='apachectl configtest' # Apache Konfig testen
alias apache-l='apachectl configtest && apachectl graceful' # Apache testen und sanft restart
alias apache-r='apachectl configtest && systemctl restart apache2' # Apache testen und Chuck-Norris Like restarten
alias lamp='apachectl configtest && systemctl restart apache2 && systemctl restart mysql' # Apache testen und den LAMP-Stack restarten

wwwalias() { alias | grep 'apache' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }
