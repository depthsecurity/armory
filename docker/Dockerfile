FROM debian:unstable-slim
MAINTAINER dlawson@depthsecurity.com
RUN echo "deb-src http://deb.debian.org/debian bullseye main" >> /etc/apt/sources.list
CMD ["echo", "Installing Debian packages needed."]
RUN apt update && apt install -y python2 python3 git python3-pip python-pip libmariadb-dev-compat wget ruby ruby-dev gem p7zip-full dnsrecon hydra whois git gcc make libpcap-dev libnet-ssleay-perl build-essential zlib1g-dev golang sudo chromium xclip libpq-dev unixodbc-dev
WORKDIR /opt/src
CMD ["echo", "Cloning various repos"]
RUN git clone https://github.com/joaomatosf/jexboss.git
RUN git clone https://github.com/fang0654/linkedint
RUN git clone https://github.com/robertdavidgraham/masscan
RUN git clone https://github.com/sullo/nikto
RUN git clone https://github.com/m8r0wn/pymeta
RUN git clone https://github.com/rbsec/sslscan.git
RUN git clone https://github.com/aboul3la/Sublist3r.git
RUN git clone https://github.com/anshumanbh/tko-subs.git
RUN git clone https://github.com/DanMcInerney/xsscrapy.git
RUN git clone https://github.com/fang0654/Asnlookup.git
RUN git clone https://github.com/vysec/DomLink.git
RUN git clone https://github.com/ztgrace/changeme.git
RUN git clone https://github.com/BishopFox/spoofcheck.git
RUN go get github.com/ffuf/ffuf
RUN ln -s /root/go/bin/ffuf /usr/local/bin/ffuf
RUN gem install aquatone
RUN go get github.com/OJ/gobuster
RUN ln -s /root/go/bin/gobuster /usr/local/bin/gobuster
RUN go get github.com/sensepost/gowitness
RUN ln -s /root/go/bin/gowitness /usr/local/bin/gowitness
RUN go get github.com/projectdiscovery/subfinder/cmd/subfinder
RUN ln -s /root/go/bin/subfinder /usr/local/bin/subfinder
WORKDIR /opt/src/jexboss
RUN pip install -r requires.txt
RUN ln -s /opt/src/jexboss/jexboss.py /usr/local/bin/jexboss.py
WORKDIR /opt/src/LinkedInt
RUN pip install thready
RUN ln -s /opt/src/linkedint/LinkedInt.py /usr/local/bin/LinkedInt.py
WORKDIR /opt/src/changeme
RUN pip install -r requirements.txt
RUN ln -s /opt/src/changeme/changeme.py /usr/local/bin/changeme.py
WORKDIR /opt/src/spoofcheck
RUN pip2 install -r requirements.txt
RUN ln -s /opt/src/spoofcheck/spoofcheck.py /usr/local/bin/spoofcheck.py
WORKDIR /opt/src/masscan
RUN make -j
RUN make install
RUN ln -s /opt/src/nikto/program /opt/nikto
RUN ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto
WORKDIR /opt/src/pymeta
RUN chmod +x setup.sh
RUN ./setup.sh
RUN chmod +x pymeta.py
RUN ln -s /opt/src/pymeta/pymeta.py /usr/local/bin/pymeta
WORKDIR /opt/src/sslscan
RUN apt-get build-dep openssl -y
RUN make static
RUN ln -s /opt/src/sslscan/sslscan /usr/local/bin/sslscan
WORKDIR /opt/src/Sublist3r
RUN pip install -r requirements.txt
RUN ln -s /opt/src/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
RUN go get github.com/anshumanbh/tko-subs
RUN ln -s /root/go/bin/tko-subs /usr/local/bin/tko-subs
RUN ln -s /root/go/src/github.com/anshumanbh/tko-subs/providers-data.csv /usr/local/bin/providers-data.csv
WORKDIR /opt/src/xsscrapy
RUN pip install -r requirements.txt
ENV PATH="${PATH}:/opt/src/xsscrapy"
RUN chmod +x /opt/src/xsscrapy/xsscrapy.py
RUN export PATH=$PATH:/opt/src/xsscrapy
RUN ln -s /opt/src/Asnlookup/asnlookup.py /usr/local/bin/asnlookup.py
RUN chmod +x /usr/local/bin/asnlookup.py
RUN ln -s /opt/src/DomLink/domLink.py /usr/local/bin/domLink.py
RUN chmod +x /usr/local/bin/domLink.py
# The nmap included with debian seems to be crashing for me under certain circumstances when using -sV. Going to try building from scratch instead.
WORKDIR /opt/src/nmap
RUN wget https://nmap.org/dist/nmap-7.80.tar.bz2

# RUN apt build-dep nmap -y
# RUN apt update && apt install binutils-mingw-w64-i686 bison flex gcc-mingw-w64-base gcc-mingw-w64-i686 gir1.2-gtk-2.0 gir1.2-harfbuzz-0.0 icu-devtools libatk1.0-dev libblas-dev libblas3 libblkid-dev libcairo-script-interpreter2 libcairo2-dev   libffi-dev libfontconfig1-dev libfreetype-dev libfreetype6-dev libfribidi-dev libgcrypt20-dev libgdk-pixbuf2.0-dev libglib2.0-dev libglib2.0-dev-bin libgpg-error-dev libgraphite2-dev libgtk2.0-0 libgtk2.0-common libgtk2.0-dev libharfbuzz-dev libharfbuzz-gobject0 libharfbuzz-icu0 libice-dev libicu-dev liblinear-dev liblua5.3-0 liblua5.3-dev liblzo2-2 libmount-dev libncurses-dev libpango1.0-dev   libpcre16-3 libpcre2-16-0 libpcre2-32-0 libpcre2-dev libpcre2-posix0 libpcre3-dev libpcre32-3 libpcrecpp0v5 libpcsclite1 libpixman-1-dev libpng-dev libpthread-stubs0-dev libreadline-dev libselinux1-dev libsepol1-dev libsm-dev libssh2-1-dev libssl-dev libx11-dev libxau-dev libxcb-render0-dev libxcb-shm0-dev libxcb1-dev libxcomposite-dev libxcursor-dev libxdamage-dev libxdmcp-dev libxext-dev libxfixes-dev libxft-dev libxi-dev libxinerama-dev libxml2-utils libxrandr-dev  libxrender-dev lua-lpeg lua-lpeg-dev mingw-w64-common mingw-w64-i686-dev pango1.0-tools uuid-dev x11proto-composite-dev x11proto-core-dev x11proto-damage-dev x11proto-dev x11proto-fixes-dev x11proto-input-dev x11proto-randr-dev x11proto-xext-dev x11proto-xinerama-dev xorg-sgml-doctools xtrans-dev -y

RUN apt update && apt install nmap -y
RUN bzip2 -cd nmap-7.80.tar.bz2 | tar xvf -
WORKDIR /opt/src/nmap/nmap-7.80
RUN ./configure
RUN make
RUN make install

WORKDIR /opt/src
# Going to increment this everytime I want to update armory.
RUN touch /tmp/revision19
RUN git clone https://github.com/depthsecurity/armory.git
WORKDIR /opt/src/armory
CMD ["echo", "Installing Armory"]
RUN python3 setup.py install
RUN pip3 install jinja2 xlsxwriter
WORKDIR /root/current
