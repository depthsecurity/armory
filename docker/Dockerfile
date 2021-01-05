FROM debian:stable-slim
MAINTAINER dlawson@depthsecurity.com

ENV DEBIAN_FRONTEND noninteractive
ENV GOROOT /opt/src/golang/go
ENV GOPATH /root/go
RUN echo "deb-src http://deb.debian.org/debian buster main" >> /etc/apt/sources.list
CMD ["echo", "Installing Debian packages needed."]


RUN apt update && apt install -y python python3 git python3-pip python-pip libmariadb-dev-compat wget ruby ruby-dev gem p7zip-full dnsrecon hydra nmap whois git gcc make libpcap-dev libnet-ssleay-perl build-essential zlib1g-dev sudo chromium xclip nano redis-server tmux

WORKDIR /opt/src/golang
RUN wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
RUN tar zxfv go1.14.2.linux-amd64.tar.gz
RUN ln -s /opt/src/golang/go/bin/go /usr/local/bin/
RUN ln -s /opt/src/golang/go/bin/gofmt /usr/local/bin/
RUN mkdir /root/go

WORKDIR /opt/src

CMD ["echo", "Cloning various repos"]
RUN git clone https://github.com/joaomatosf/jexboss.git
RUN touch /tmp/linkedint2
RUN git clone https://github.com/fang0654/LinkedInt
RUN git clone https://github.com/robertdavidgraham/masscan
RUN git clone https://github.com/sullo/nikto
RUN git clone https://github.com/m8r0wn/pymeta
RUN git clone https://github.com/rbsec/sslscan.git
RUN git clone https://github.com/aboul3la/Sublist3r.git
RUN git clone https://github.com/anshumanbh/tko-subs.git
RUN git clone https://github.com/DanMcInerney/xsscrapy.git
RUN git clone https://github.com/fang0654/Asnlookup.git
RUN git clone https://github.com/laramies/theHarvester
RUN git clone https://github.com/projectdiscovery/subfinder.git
RUN touch /tmp/update1

RUN git clone https://github.com/fang0654/DomLink.git
RUN git clone https://github.com/offensive-security/exploitdb.git

# RUN go get github.com/ffuf/ffuf

# Next couple of lines are to use custom version of ffuf until it gets updated
RUN go get github.com/ffuf/ffuf

RUN ln -s /root/go/bin/ffuf /usr/local/bin/ffuf
RUN gem install aquatone
RUN go get github.com/OJ/gobuster
RUN ln -s /root/go/bin/gobuster /usr/local/bin/gobuster

# Gowitness doesn't seem to be building right now - will just use the latest (at the time) release

# RUN go get github.com/sensepost/gowitness
# RUN ln -s /root/go/bin/gowitness /usr/local/bin/gowitness

RUN wget https://github.com/sensepost/gowitness/releases/download/2.1.1/gowitness-2.1.1-linux-amd64 -O /usr/local/bin/gowitness
RUN chmod +x /usr/local/bin/gowitness

#RUN go get github.com/projectdiscovery/subfinder/cmd/subfinder

#RUN GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

WORKDIR /opt/src/subfinder/v2/cmd/subfinder
RUN go build .
RUN ln -s /opt/src/subfinder/v2/cmd/subfinder/subfinder /usr/local/bin/subfinder
#RUN ln -s /root/go/bin/subfinder /usr/local/bin/subfinder
# Run this to create the subfinder config, so it doesn't create a race condition causing others to error out as multiple threads try to create it at once
RUN /usr/local/bin/subfinder -d domainthatdoesnotexits.biz -sources shodan

RUN go get github.com/hakluke/hakrawler
RUN ln -s /root/go/bin/hakrawler /usr/local/bin/hakrawler
WORKDIR /opt/src/jexboss
RUN pip install -r requires.txt
RUN ln -s /opt/src/jexboss/jexboss.py /usr/local/bin/jexboss.py
WORKDIR /opt/src/LinkedInt
RUN pip install thready http
RUN chmod +x /opt/src/LinkedInt/LinkedInt.py
RUN ln -s /opt/src/LinkedInt/LinkedInt.py /usr/local/bin/LinkedInt.py
WORKDIR /opt/src/masscan
RUN make -j
RUN make install
RUN ln -s /opt/src/nikto/program /opt/nikto
RUN ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto
WORKDIR /opt/src/pymeta
RUN python3 setup.py install
RUN chmod +x pymeta.py

WORKDIR /opt/src/sslscan
RUN apt-get build-dep openssl -y
# RUN sed -i 's/fPIE/fPIC/g' Makefile
RUN make static

RUN ln -s /opt/src/sslscan/sslscan /usr/local/bin/sslscan
WORKDIR /opt/src/Sublist3r
RUN pip install -r requirements.txt
RUN ln -s /opt/src/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
RUN go get github.com/anshumanbh/tko-subs
RUN ln -s /root/go/bin/tko-subs /usr/local/bin/tko-subs
RUN ln -s /root/go/src/github.com/anshumanbh/tko-subs/providers-data.csv /usr/local/bin/providers-data.csv


# Install amass - for whatever reason, I haven't been able to get the go get to work
#ENV GO111MODULE on
#RUN go get -v github.com/OWASP/Amass/v3
#RUN ln -s /root/go/bin/amass /usr/local/bin/amass

WORKDIR /opt/src/amass
RUN wget https://github.com/OWASP/Amass/releases/download/v3.10.2/amass_linux_amd64.zip
RUN unzip amass_linux_amd64.zip
RUN ln -s /opt/src/amass/amass_linux_amd64/amass /usr/local/bin/

WORKDIR /opt/src/xsscrapy
RUN pip install -r requirements.txt
ENV PATH="${PATH}:/opt/src/xsscrapy"
RUN chmod +x /opt/src/xsscrapy/xsscrapy.py
RUN export PATH=$PATH:/opt/src/xsscrapy
RUN ln -s /opt/src/Asnlookup/asnlookup.py /usr/local/bin/asnlookup.py
RUN chmod +x /usr/local/bin/asnlookup.py
RUN ln -s /opt/src/DomLink/domLink.py /usr/local/bin/domLink.py
RUN chmod +x /usr/local/bin/domLink.py

WORKDIR /opt/src/theHarvester
RUN pip3 install -r requirements.txt
RUN python3 setup.py install


RUN sed -i 's/\/opt\/exploitdb/\/opt\/src\/exploitdb/g' /opt/src/exploitdb/.searchsploit_rc
RUN cp /opt/src/exploitdb/.searchsploit_rc /root/
RUN ln -s /opt/src/exploitdb/searchsploit /usr/local/bin/searchsploit

WORKDIR /opt/src

# Going to increment this everytime I want to update armory.
RUN touch /tmp/revision136




RUN git clone https://github.com/depthsecurity/armory.git
WORKDIR /opt/src/armory
RUN git checkout armory2.0
CMD ["echo", "Installing Armory"]
RUN pip3 install django # Not sure why this doesn't work from the setup
RUN python3 setup.py install
RUN pip3 install jinja2 xlsxwriter django_q
WORKDIR /root/current
COPY launch_api.sh /usr/bin/launch_api.sh
RUN chmod +x /usr/bin/launch_api.sh
