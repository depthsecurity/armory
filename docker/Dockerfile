FROM debian:buster-slim
MAINTAINER dlawson@depthsecurity.com

RUN echo "deb-src http://deb.debian.org/debian buster main" >> /etc/apt/sources.list
RUN apt update
CMD ["echo", "Installing Debian packages needed."]
RUN apt install -y python2 python3 git python3-pip python-pip libmariadb-dev-compat wget ruby ruby-dev gem p7zip-full dnsrecon hydra nmap whois git gcc make libpcap-dev libnet-ssleay-perl build-essential zlib1g-dev golang
WORKDIR /opt/src
CMD ["echo", "Cloning various repos"]
RUN git clone https://github.com/depthsecurity/armory.git
RUN git clone https://github.com/joaomatosf/jexboss.git
RUN git clone https://github.com/fang0654/linkedint
RUN git clone https://github.com/robertdavidgraham/masscan
RUN git clone https://github.com/sullo/nikto
RUN git clone https://github.com/m8r0wn/pymeta
RUN git clone https://github.com/rbsec/sslscan.git
RUN git clone https://github.com/aboul3la/Sublist3r.git
RUN git clone https://github.com/anshumanbh/tko-subs.git
RUN git clone https://github.com/DanMcInerney/xsscrapy.git
WORKDIR /opt/src/armory
CMD ["echo", "Installing Armory"]
RUN python3 setup.py install
RUN go get github.com/ffuf/ffuf
RUN ln -s /root/go/bin/ffuf /usr/local/bin/ffuf
RUN gem install aquatone
RUN go get github.com/OJ/gobuster
RUN ln -s /root/go/bin/gobuster /usr/local/bin/gobuster
RUN go get github.com/sensepost/gowitness
RUN ln -s /root/go/bin/gowitness /usr/local/bin/gowitness
WORKDIR /opt/src/jexboss
RUN pip install -r requires.txt
RUN ln -s /opt/src/jexboss/jexboss.py /usr/local/bin/jexboss.py
WORKDIR /opt/src/LinkedInt
RUN pip install thready
RUN ln -s /opt/src/linkedint/LinkedInt.py /usr/local/bin/LinkedInt.py
WORKDIR /opt/src/masscan
RUN make -j
RUN make install
RUN ln -s /opt/src/nikto/program /opt/nikto
RUN ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto
WORKDIR /opt/src/pymeta
RUN chmod +x setup.sh
RUN ./setup.sh
RUN chmod +x pymeta.py
RUN ln -s /opt/src/pymeta/pymeta.py /usr/local/bin/pymeta.py
WORKDIR /opt/src/sslscan
RUN apt-get build-dep openssl -y
RUN make static
RUN ln -s /opt/src/sslscan/sslscan /usr/local/bin/sslscan
WORKDIR /opt/src/subfinder
RUN wget https://github.com/subfinder/subfinder/releases/download/1.0/subfinder_linux_amd64_1.0.zip
RUN unzip subfinder_linux_amd64_1.0.zip
RUN ln -s /opt/src/subfinder/subfinder /usr/local/bin/subfinder
WORKDIR /opt/src/Sublist3r
RUN pip install -r requirements.txt
RUN ln -s /opt/src/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
RUN go get github.com/anshumanbh/tko-subs
RUN ln -s /root/go/bin/tko-subs /usr/local/bin/tko-subs
WORKDIR /opt/src/xsscrapy
RUN pip install -r requirements.txt
WORKDIR /root/current
