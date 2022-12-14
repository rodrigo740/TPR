# archlinux build with SSH and botnet

# get arch linux image
FROM archlinux:latest

# update the repositories
RUN pacman -Syu --noconfirm

# install needed packages
RUN pacman -S --noconfirm openssh vim git python stunnel

# copy botnet files into the container
COPY TPR .
COPY miniircd .

# generate host keys
RUN /usr/bin/ssh-keygen -A

# add password to root user (username:password)
RUN echo 'root:root' | chpasswd

# allow ssh root login
RUN  sed -i -e 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config

# run openssh daemon
CMD ["/usr/sbin/sshd", "-D"]
